package controller

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"trojan/core"

	"github.com/robfig/cron/v3"
)

const accessHistoryLookback = 30 * 24 * time.Hour

var (
	accessHistoryCron *cron.Cron
	accessHistoryMu   sync.Mutex
	accessLogPattern  = regexp.MustCompile(`(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) user ([0-9a-f]{56}) from (.+?):\d+ tunneling to (.+):(\d+) closed sent: ([0-9.]+) ([A-Za-z]+) recv: ([0-9.]+) ([A-Za-z]+)`)
)

type accessHistoryRow struct {
	Username    string `json:"username"`
	UserHash    string `json:"userHash"`
	TargetHost  string `json:"targetHost"`
	ClientIP    string `json:"clientIP"`
	AccessCount uint64 `json:"accessCount"`
	Upload      uint64 `json:"upload"`
	Download    uint64 `json:"download"`
}

type accessHistoryUserGroup struct {
	Username      string `json:"username"`
	UserHash      string `json:"userHash"`
	TargetCount   uint64 `json:"targetCount"`
	AccessCount   uint64 `json:"accessCount"`
	ClientIPCount uint64 `json:"clientIPCount"`
}

type accessHistoryDetailPage struct {
	UserHash string             `json:"userHash"`
	Page     int                `json:"page"`
	PageSize int                `json:"pageSize"`
	Total    int                `json:"total"`
	Items    []accessHistoryRow `json:"items"`
}

type accessHistoryStat struct {
	StatDate    string
	UserHash    string
	TargetHost  string
	TargetPort  int
	ClientIP    string
	AccessCount uint64
	Upload      uint64
	Download    uint64
}

type accessHistoryCollectResult struct {
	From        string `json:"from"`
	Until       string `json:"until"`
	Scanned     int    `json:"scanned"`
	Matched     int    `json:"matched"`
	Aggregated  int    `json:"aggregated"`
	LastCollect string `json:"lastCollect"`
}

type accessHistoryStatus struct {
	LastCollect string `json:"lastCollect"`
}

func ensureAccessHistoryTables(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS access_history_stats (
			stat_date DATE NOT NULL,
			user_hash CHAR(56) NOT NULL,
			target_host VARCHAR(255) NOT NULL,
			target_port INT NOT NULL DEFAULT 0,
			client_ip VARCHAR(45) NOT NULL,
			access_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
			upload BIGINT UNSIGNED NOT NULL DEFAULT 0,
			download BIGINT UNSIGNED NOT NULL DEFAULT 0,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY (stat_date, user_hash, target_host, target_port, client_ip),
			INDEX idx_access_history_date (stat_date),
			INDEX idx_access_history_user (user_hash),
			INDEX idx_access_history_host (target_host)
		) DEFAULT CHARSET=utf8mb4;`,
		`CREATE TABLE IF NOT EXISTS access_history_meta (
			meta_key VARCHAR(64) NOT NULL,
			meta_value VARCHAR(255) NOT NULL,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY (meta_key)
		) DEFAULT CHARSET=utf8mb4;`,
	}
	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			return err
		}
	}
	return nil
}

func accessHistoryDB() (*sql.DB, error) {
	mysql := core.GetMysql()
	db := mysql.GetDB()
	if db == nil {
		return nil, errors.New("连接mysql失败")
	}
	if err := ensureAccessHistoryTables(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func accessHistoryLastCollect(db *sql.DB) (time.Time, string, error) {
	var value string
	err := db.QueryRow("SELECT meta_value FROM access_history_meta WHERE meta_key='last_collect_utc'").Scan(&value)
	if err == sql.ErrNoRows || value == "" {
		return time.Now().UTC().Add(-accessHistoryLookback), "", nil
	}
	if err != nil {
		return time.Time{}, "", err
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, value, err
	}
	return t.UTC(), value, nil
}

func byteValue(num, unit string) uint64 {
	value, _ := strconv.ParseFloat(num, 64)
	multiplier := float64(1)
	switch strings.ToLower(unit) {
	case "kib", "kb":
		multiplier = 1024
	case "mib", "mb":
		multiplier = 1024 * 1024
	case "gib", "gb":
		multiplier = 1024 * 1024 * 1024
	case "tib", "tb":
		multiplier = 1024 * 1024 * 1024 * 1024
	}
	return uint64(value * multiplier)
}

func cleanClientIP(value string) string {
	return strings.Trim(strings.TrimSpace(value), "[]")
}

func parseAccessLogLine(line string, china *time.Location) (accessHistoryStat, bool) {
	match := accessLogPattern.FindStringSubmatch(line)
	if len(match) != 10 {
		return accessHistoryStat{}, false
	}
	utcTime, err := time.ParseInLocation("2006/01/02 15:04:05", match[1], time.UTC)
	if err != nil {
		return accessHistoryStat{}, false
	}
	port, _ := strconv.Atoi(match[5])
	return accessHistoryStat{
		StatDate:    utcTime.In(china).Format("2006-01-02"),
		UserHash:    match[2],
		ClientIP:    cleanClientIP(match[3]),
		TargetHost:  strings.TrimSpace(match[4]),
		TargetPort:  port,
		AccessCount: 1,
		Upload:      byteValue(match[6], match[7]),
		Download:    byteValue(match[8], match[9]),
	}, true
}

func collectAccessHistory(db *sql.DB) (*accessHistoryCollectResult, error) {
	accessHistoryMu.Lock()
	defer accessHistoryMu.Unlock()

	from, _, err := accessHistoryLastCollect(db)
	if err != nil {
		return nil, err
	}
	from = from.Add(time.Second)
	until := time.Now().UTC()
	if !from.Before(until) {
		return &accessHistoryCollectResult{
			From:        from.Format(time.RFC3339),
			Until:       until.Format(time.RFC3339),
			LastCollect: until.Format(time.RFC3339),
		}, setAccessHistoryLastCollect(db, until)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "journalctl", "-u", "trojan.service", "--since", from.Format("2006-01-02 15:04:05 UTC"), "--until", until.Format("2006-01-02 15:04:05 UTC"), "--no-pager", "-o", "cat")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	china, _ := time.LoadLocation("Asia/Shanghai")
	stats := map[string]*accessHistoryStat{}
	result := &accessHistoryCollectResult{
		From:  from.Format(time.RFC3339),
		Until: until.Format(time.RFC3339),
	}
	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		result.Scanned++
		stat, ok := parseAccessLogLine(scanner.Text(), china)
		if !ok {
			continue
		}
		result.Matched++
		key := strings.Join([]string{stat.StatDate, stat.UserHash, stat.TargetHost, strconv.Itoa(stat.TargetPort), stat.ClientIP}, "\x00")
		existing := stats[key]
		if existing == nil {
			copyStat := stat
			stats[key] = &copyStat
			continue
		}
		existing.AccessCount += stat.AccessCount
		existing.Upload += stat.Upload
		existing.Download += stat.Download
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, errors.New("访问历史收集超时")
		}
		return nil, err
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	stmt, err := tx.Prepare(`INSERT INTO access_history_stats(stat_date, user_hash, target_host, target_port, client_ip, access_count, upload, download)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE access_count=access_count+VALUES(access_count), upload=upload+VALUES(upload), download=download+VALUES(download)`)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	for _, stat := range stats {
		if _, err := stmt.Exec(stat.StatDate, stat.UserHash, stat.TargetHost, stat.TargetPort, stat.ClientIP, stat.AccessCount, stat.Upload, stat.Download); err != nil {
			stmt.Close()
			tx.Rollback()
			return nil, err
		}
	}
	stmt.Close()
	if err := setAccessHistoryLastCollect(tx, until); err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	result.Aggregated = len(stats)
	result.LastCollect = until.Format(time.RFC3339)
	return result, nil
}

type accessHistoryExec interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
}

func setAccessHistoryLastCollect(exec accessHistoryExec, value time.Time) error {
	_, err := exec.Exec(`INSERT INTO access_history_meta(meta_key, meta_value) VALUES('last_collect_utc', ?)
		ON DUPLICATE KEY UPDATE meta_value=VALUES(meta_value)`, value.UTC().Format(time.RFC3339Nano))
	return err
}

func AccessHistoryList(startDate, endDate, userHash, targetHost, detailUserHash string, page, pageSize int) *ResponseBody {
	responseBody := ResponseBody{Msg: "success"}
	defer TimeCost(time.Now(), &responseBody)

	db, err := accessHistoryDB()
	if err != nil {
		responseBody.Msg = err.Error()
		return &responseBody
	}
	defer db.Close()

	china, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Now().In(china)
	if endDate == "" {
		endDate = now.Format("2006-01-02")
	}
	if startDate == "" {
		startDate = now.AddDate(0, 0, -7).Format("2006-01-02")
	}

	conditions := []string{"s.stat_date BETWEEN ? AND ?"}
	args := []interface{}{startDate, endDate}
	if userHash != "" {
		conditions = append(conditions, "s.user_hash = ?")
		args = append(args, userHash)
	}
	if targetHost != "" {
		conditions = append(conditions, "s.target_host LIKE ?")
		args = append(args, "%"+targetHost+"%")
	}

	groupQuery := fmt.Sprintf(`SELECT COALESCE(u.username, s.user_hash) AS username, s.user_hash,
			COUNT(DISTINCT s.target_host) AS target_count,
			SUM(s.access_count) AS access_count,
			COUNT(DISTINCT s.client_ip) AS client_ip_count
		FROM access_history_stats s
		LEFT JOIN users u ON u.password = s.user_hash
		WHERE %s
		GROUP BY username, s.user_hash
		ORDER BY access_count DESC, username ASC`, strings.Join(conditions, " AND "))

	rows, err := db.Query(groupQuery, args...)
	if err != nil {
		responseBody.Msg = err.Error()
		return &responseBody
	}
	defer rows.Close()

	groups := make([]accessHistoryUserGroup, 0)
	for rows.Next() {
		var group accessHistoryUserGroup
		if err := rows.Scan(&group.Username, &group.UserHash, &group.TargetCount, &group.AccessCount, &group.ClientIPCount); err != nil {
			responseBody.Msg = err.Error()
			return &responseBody
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		responseBody.Msg = err.Error()
		return &responseBody
	}

	_, lastValue, _ := accessHistoryLastCollect(db)
	data := map[string]interface{}{
		"groups":      groups,
		"startDate":   startDate,
		"endDate":     endDate,
		"lastCollect": lastValue,
	}
	if detailUserHash != "" {
		detail, err := accessHistoryDetail(db, startDate, endDate, targetHost, detailUserHash, page, pageSize)
		if err != nil {
			responseBody.Msg = err.Error()
			return &responseBody
		}
		data["detail"] = detail
	}
	responseBody.Data = data
	return &responseBody
}

func accessHistoryDetail(db *sql.DB, startDate, endDate, targetHost, userHash string, page, pageSize int) (*accessHistoryDetailPage, error) {
	if page < 1 {
		page = 1
	}
	if pageSize != 100 {
		pageSize = 50
	}
	conditions := []string{"s.stat_date BETWEEN ? AND ?", "s.user_hash = ?"}
	args := []interface{}{startDate, endDate, userHash}
	if targetHost != "" {
		conditions = append(conditions, "s.target_host LIKE ?")
		args = append(args, "%"+targetHost+"%")
	}
	whereSQL := strings.Join(conditions, " AND ")
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM (
		SELECT s.target_host, s.client_ip
		FROM access_history_stats s
		WHERE %s
		GROUP BY s.target_host, s.client_ip
	) t`, whereSQL)
	var total int
	if err := db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, err
	}

	detailArgs := append([]interface{}{}, args...)
	detailArgs = append(detailArgs, (page-1)*pageSize, pageSize)
	query := fmt.Sprintf(`SELECT COALESCE(u.username, s.user_hash) AS username, s.user_hash, s.target_host, s.client_ip,
			SUM(s.access_count) AS access_count, SUM(s.upload) AS upload, SUM(s.download) AS download
		FROM access_history_stats s
		LEFT JOIN users u ON u.password = s.user_hash
		WHERE %s
		GROUP BY username, s.user_hash, s.target_host, s.client_ip
		ORDER BY access_count DESC, target_host ASC
		LIMIT ?, ?`, whereSQL)
	rows, err := db.Query(query, detailArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]accessHistoryRow, 0)
	for rows.Next() {
		var item accessHistoryRow
		if err := rows.Scan(&item.Username, &item.UserHash, &item.TargetHost, &item.ClientIP, &item.AccessCount, &item.Upload, &item.Download); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &accessHistoryDetailPage{
		UserHash: userHash,
		Page:     page,
		PageSize: pageSize,
		Total:    total,
		Items:    items,
	}, nil
}

func AccessHistoryCollect() *ResponseBody {
	responseBody := ResponseBody{Msg: "success"}
	defer TimeCost(time.Now(), &responseBody)

	db, err := accessHistoryDB()
	if err != nil {
		responseBody.Msg = err.Error()
		return &responseBody
	}
	defer db.Close()

	result, err := collectAccessHistory(db)
	if err != nil {
		responseBody.Msg = err.Error()
		return &responseBody
	}
	responseBody.Data = result
	return &responseBody
}

func AccessHistoryStatus() *ResponseBody {
	responseBody := ResponseBody{Msg: "success"}
	defer TimeCost(time.Now(), &responseBody)
	db, err := accessHistoryDB()
	if err != nil {
		responseBody.Msg = err.Error()
		return &responseBody
	}
	defer db.Close()
	_, lastValue, _ := accessHistoryLastCollect(db)
	responseBody.Data = accessHistoryStatus{LastCollect: lastValue}
	return &responseBody
}

func AccessHistoryScheduleTask() {
	db, err := accessHistoryDB()
	if err != nil {
		fmt.Println("AccessHistoryInitError: " + err.Error())
	} else {
		db.Close()
	}
	loc, _ := time.LoadLocation("Asia/Shanghai")
	accessHistoryCron = cron.New(cron.WithLocation(loc))
	accessHistoryCron.AddFunc("0 4 * * *", func() {
		db, err := accessHistoryDB()
		if err != nil {
			fmt.Println("AccessHistoryDBError: " + err.Error())
			return
		}
		defer db.Close()
		if _, err := collectAccessHistory(db); err != nil {
			fmt.Println("AccessHistoryCollectError: " + err.Error())
		}
	})
	accessHistoryCron.Start()
}
