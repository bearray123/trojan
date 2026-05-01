package controller

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"
	"trojan/core"
)

type certInfo struct {
	CertPath     string    `json:"certPath"`
	KeyPath      string    `json:"keyPath"`
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"notBefore"`
	NotAfter     time.Time `json:"notAfter"`
	DNSNames     []string  `json:"dnsNames"`
	IPAddresses  []string  `json:"ipAddresses"`
	SerialNumber string    `json:"serialNumber"`
	DaysLeft     int       `json:"daysLeft"`
}

func loadCertificateInfo() (*certInfo, error) {
	config := core.GetConfig()
	if config == nil {
		return nil, errors.New("load config failed")
	}
	data, err := os.ReadFile(config.SSl.Cert)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid certificate pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	ipList := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ipList = append(ipList, ip.String())
	}
	return &certInfo{
		CertPath:     config.SSl.Cert,
		KeyPath:      config.SSl.Key,
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		DNSNames:     cert.DNSNames,
		IPAddresses:  ipList,
		SerialNumber: cert.SerialNumber.String(),
		DaysLeft:     int(time.Until(cert.NotAfter).Hours() / 24),
	}, nil
}

// CertInfo 获取当前TLS证书详情
func CertInfo() *ResponseBody {
	responseBody := ResponseBody{Msg: "success"}
	defer TimeCost(time.Now(), &responseBody)
	info, err := loadCertificateInfo()
	if err != nil {
		responseBody.Msg = err.Error()
		return &responseBody
	}
	responseBody.Data = info
	return &responseBody
}

// RenewCert 触发证书续签
func RenewCert() *ResponseBody {
	responseBody := ResponseBody{Msg: "success"}
	defer TimeCost(time.Now(), &responseBody)
	if _, err := os.Stat("/root/.acme.sh/acme.sh"); err != nil {
		responseBody.Msg = err.Error()
		return &responseBody
	}
	cmd := exec.Command("bash", "-c", "nohup bash -c 'systemctl stop trojan-web; /root/.acme.sh/acme.sh --cron --home /root/.acme.sh; systemctl restart trojan; systemctl start trojan-web' >/tmp/trojan-cert-renew.log 2>&1 &")
	if out, err := cmd.CombinedOutput(); err != nil {
		responseBody.Msg = strings.TrimSpace(string(out))
		if responseBody.Msg == "" {
			responseBody.Msg = err.Error()
		}
		return &responseBody
	}
	responseBody.Data = map[string]string{
		"log": "/tmp/trojan-cert-renew.log",
	}
	return &responseBody
}
