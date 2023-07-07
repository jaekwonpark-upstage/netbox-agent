package main

import (
	"context"
	"time"
	"fmt"
	"net"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"encoding/json"

	"github.com/miekg/dns"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"

	"github.com/digitalocean/go-netbox/netbox"
	"github.com/digitalocean/go-netbox/netbox/client"
	"github.com/digitalocean/go-netbox/netbox/client/dcim"
	"github.com/digitalocean/go-netbox/netbox/client/ipam"
	"github.com/digitalocean/go-netbox/netbox/client/virtualization"
)

const (
	netboxAPIURL    = "YOUR_NETBOX_API_URL"
	netboxAPIToken  = "YOUR_NETBOX_API_TOKEN"
	deviceRole      = "Server"
	region          = "Seoul"
	site            = "Temp"
	platform        = "OS 종류"
	interfaceType   = "1000BASE-T"
)

type BlockDevice struct {
        Name   string `json:"name"`
        Model  string `json:"model"`
        Vendor string `json:"vendor"`
        Size   string `json:"size"`
        Type   string `json:"type"`
	Serial string `json:"serial"` // 이 부분을 추가하세요.

}

var lsblkOutput struct {
        BlockDevices []BlockDevice `json:"blockdevices"`
}

func main() {

	vm, err := isVirtualMachine()
	if err != nil {
		fmt.Println("Error: - isVirtualMachine", err)
	} else {
		if vm {
			fmt.Println("가상 머신: 예")
			cloud, cloudProvider, err := isCloudEnvironment()
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				if cloud {
					fmt.Printf("클라우드 환경: 예 (%s)\n", cloudProvider)
				} else {
					fmt.Println("클라우드 환경: 아니오")
				}
			}
		} else {
			fmt.Println("가상 머신: 아니오")
		}
	}

	hwManufacturer, err := getHwManufacturer()
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("하드웨어 제조사:", hwManufacturer)
	}

	productName, err := getHwProductName()
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("제품명:", productName)
	}

	serialNumber, err := getHwSerialNumber()
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("S/N:", serialNumber)
	}

	osInfo, err := getOSInfo()
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("OS 종류:", osInfo)
	}

	fmt.Println("OS ARCH:", runtime.GOARCH)

	cpuCount, err := cpu.Counts(true)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("CPU 갯수:", cpuCount)
	}

	memStat, err := mem.VirtualMemory()
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("메모리: %.2f GB\n", float64(memStat.Total)/1024/1024/1024)
	}

	nics, err := net.Interfaces()
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		for _, nic := range nics {
			if isPhysicalInterface(nic.Name) && !isBridge(nic.Name) && !isLocalInterface(nic.Name) {
				fmt.Println("NIC 이름:", nic.Name)
				fmt.Println("MAC 주소:", nic.HardwareAddr)
				addresses, _ := nic.Addrs()
				for _, addr := range addresses {
					if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
						ipAddr := ipnet.IP.String()
						fmt.Println("IPv4 주소:", ipAddr)
						domain, err := getPTRRecord(ipAddr)
						if err == nil && domain != "" {
							fmt.Println("도메인 이름:", domain)
						}
					}
				}
			}
		}
	}

	pciDevices, err := getPCIDevices()
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("\nGPU 및 NIC PCI-E 장치 목록:")
		for _, device := range pciDevices {
			if isGPUDevice(device) || isNICDevice(device) {
				fmt.Println(device)
			}
		}
	}

	gpuInfos, err := getGPUInfos()
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("\nGPU 정보:")
		for index, gpuInfo := range gpuInfos {
			fmt.Printf("GPU %d:\n", index+1)
			fmt.Println("제조사:", gpuInfo["vendor"])
			fmt.Println("모델명:", gpuInfo["model"])
		}
	}
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		for _, device := range pciDevices {
			if isNICDevice(device) {
				deviceID := getDeviceID(device)
				vendor, model, err := getNICInfo(deviceID)
				if err != nil {
					fmt.Println("Error:", err)
				} else {
					deviceName, err := getNICNameByDeviceID(deviceID)
					if err != nil {
						fmt.Println("Error:", err)
					} else {
						fmt.Printf("NIC 이름: %s, 제조사: %s, 모델명: %s\n", deviceName, vendor, model)
					}
				}
			}
		}
	}

	storages, err := getStorageDevices()
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("\n스토리지 장치 정보:")
		for _, storage := range storages {
			fmt.Printf("제조사: %s, 모델: %s, 용량: %s, 시리얼 번호: %s\n", storage["vendor"], storage["model"], storage["size"], storage["serial"])
		}
	}


	err = installIPMITool()
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		err = printIPMISystemLogs()
		if err != nil {
			fmt.Println("Error:", err)
		}
	}

	// Netbox API 클라이언트 생성
	httpClient := &http.Client{}
	netboxClient, err := netbox.NewNetboxWithAPIKey(netboxAPIURL, httpClient, netboxAPIToken)
	if err != nil {
		log.Fatalf("Failed to create Netbox client: %v", err)
	}

	// 도메인 이름으로 Devices 검색 및 생성
	deviceID, err := searchOrCreateDevice(netboxClient, domainName)
	if err != nil {
		log.Fatalf("Failed to search or create device: %v", err)
	}

	// Components 추가
	err = addComponents(netboxClient, deviceID)
	if err != nil {
		log.Fatalf("Failed to add components: %v", err)
	}



}


func getHwManufacturer() (string, error) {
	cmd := exec.Command("sudo", "dmidecode", "-t", "system")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "Manufacturer:") {
			manufacturer := strings.TrimPrefix(strings.TrimSpace(line), "Manufacturer:")
			return strings.TrimSpace(manufacturer), nil
		}
	}

	return "", fmt.Errorf("manufacturer information not found")
}

func getHwProductName() (string, error) {
	cmd := exec.Command("sudo", "dmidecode", "-t", "system")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "Product Name:") {
			productName := strings.TrimPrefix(strings.TrimSpace(line), "Product Name:")
			return strings.TrimSpace(productName), nil
		}
	}

	return "", fmt.Errorf("product name information not found")
}

func getHwSerialNumber() (string, error) {
	cmd := exec.Command("sudo", "dmidecode", "-t", "system")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "Serial Number:") {
			serialNumber := strings.TrimPrefix(strings.TrimSpace(line), "Serial Number:")
			return strings.TrimSpace(serialNumber), nil
		}
	}

	return "", fmt.Errorf("serial number information not found")
}

func isBridge(name string) bool {
	bridgePath := filepath.Join("/sys/class/net", name, "bridge")
	_, err := os.Stat(bridgePath)
	return !os.IsNotExist(err)
}

func isLocalInterface(name string) bool {
	return strings.HasPrefix(name, "lo")
}


func isGPUDevice(device string) bool {
	device = strings.ToLower(device)
	return strings.Contains(device, "vga") || strings.Contains(device, "3d controller") || strings.Contains(device, "display")
}

func isStorageDevice(device string) bool {
	return strings.Contains(strings.ToLower(device), "storage") || strings.Contains(strings.ToLower(device), "nvme") || strings.Contains(strings.ToLower(device), "mass storage")
}

func isPhysicalInterface(name string) bool {
	devicePath := filepath.Join("/sys/class/net", name, "device")
	_, err := os.Stat(devicePath)
	return !os.IsNotExist(err)
}

func getGPUInfos() ([]map[string]string, error) {
	updateCmd := exec.Command("sudo", "update-pciids")
	updateErr := updateCmd.Run()
	if updateErr != nil {
		return nil, updateErr
	}

	cmd := exec.Command("lshw", "-C", "display")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	var gpuInfos []map[string]string
	var gpuInfo map[string]string
	for _, line := range lines {
		if strings.Contains(line, "*-display") {
			if gpuInfo != nil {
				gpuInfos = append(gpuInfos, gpuInfo)
			}
			gpuInfo = make(map[string]string)
		} else if strings.Contains(line, "vendor:") {
			trimmed := strings.TrimSpace(line)
			vendor := strings.TrimPrefix(trimmed, "vendor:")
			gpuInfo["vendor"] = strings.TrimSpace(vendor)
		} else if strings.Contains(line, "product:") {
			trimmed := strings.TrimSpace(line)
			product := strings.TrimPrefix(trimmed, "product:")
			gpuInfo["model"] = strings.TrimSpace(product)
		}
	}

	if gpuInfo != nil {
		gpuInfos = append(gpuInfos, gpuInfo)
	}

	return gpuInfos, nil
}

func getOSInfo() (string, error) {
	cmd := exec.Command("lsb_release", "-d")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	osInfo := strings.TrimSpace(strings.Split(string(output), ":")[1])
	return osInfo, nil
}

func getPTRRecord(ipAddr string) (string, error) {
	ipReversed, err := dns.ReverseAddr(ipAddr)
	if err != nil {
		return "", err
	}

	m := new(dns.Msg)
	m.SetQuestion(ipReversed, dns.TypePTR)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, "ns.ssh.upstage.host:53")

	if err != nil {
		return "", err
	}

	if len(in.Answer) > 0 {
		if ptr, ok := in.Answer[0].(*dns.PTR); ok {
			return strings.TrimSuffix(ptr.Ptr, "."), nil
		}
	}

	return "", nil
}


func getPCIDevices() ([]string, error) {
	// 수정된 부분: context.WithTimeout을 사용하여 5초의 타임아웃을 설정합니다.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 수정된 부분: exec.CommandContext를 사용하여 명령을 실행합니다.
	cmd := exec.CommandContext(ctx, "lspci")
	output, err := cmd.Output()

	// 타임아웃이 발생한 경우 에러를 처리합니다.
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("lspci command timed out")
	}

	if err != nil {
		combinedOutput, _ := cmd.CombinedOutput()
		return nil, fmt.Errorf("lspci command error: %v, detailed error: %s", err, string(combinedOutput))
	}

	lines := strings.Split(string(output), "\n")
	var devices []string
	for _, line := range lines {
		if len(line) > 0 {
			devices = append(devices, line)
		}
	}

	return devices, nil
}


func isNICDevice(device string) bool {
	device = strings.ToLower(device)
	return strings.Contains(device, "network") || strings.Contains(device, "ethernet") || strings.Contains(device, "infiniband")
}


func getDeviceID(device string) string {
	fields := strings.Fields(device)
	if len(fields) > 0 {
		return fields[0]
	}
	return ""
}

func getNICInfo(deviceID string) (string, string, error) {
	cmd := exec.Command("lspci", "-vmks", deviceID)
	output, err := cmd.Output()
	if err != nil {
		return "", "", err
	}

	lines := strings.Split(string(output), "\n")
	var vendor, model string
	for _, line := range lines {
		if strings.Contains(line, "Vendor:") {
			vendor = strings.TrimSpace(strings.Split(line, ":")[1])
		} else if strings.Contains(line, "Device:") {
			model = strings.TrimSpace(strings.Split(line, ":")[1])
		}
	}

	return vendor, model, nil
}

func getNICNameByDeviceID(deviceID string) (string, error) {
	cmd := exec.Command("find", "/sys/class/net", "-mindepth", "1", "-maxdepth", "1", "-exec", "readlink", "-f", "{}", ";")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, deviceID) {
			nicName := filepath.Base(line)
			return nicName, nil
		}
	}

	return "", fmt.Errorf("no interface name found for device ID %s", deviceID)
}


func isVirtualMachine() (bool, error) {
	cmd := exec.Command("systemd-detect-virt")
	output, err := cmd.Output()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			// systemd-detect-virt returns exit code 1 when not in a virtual machine
			if exitError.ExitCode() == 1 {
				return false, nil
			}
		}
		return false, fmt.Errorf("systemd-detect-virt command error: %v", err)
	}

	detectedVirt := strings.TrimSpace(string(output))
	return detectedVirt != "none", nil
}

func isCloudEnvironment() (bool, string, error) {
	cmd := exec.Command("sudo", "dmidecode", "-s", "system-manufacturer")
	output, err := cmd.Output()
	if err != nil {
		return false, "", err
	}

	manufacturer := strings.TrimSpace(string(output))
	cloudProviders := map[string]string{
		"Amazon EC2": "Amazon Web Services",
		"Google":     "Google Cloud Platform",
		"Microsoft":  "Microsoft Azure",
		"QEMU":       "QEMU",
		"VMware":     "VMware",
	}

	for provider, name := range cloudProviders {
		if strings.Contains(manufacturer, provider) {
			return true, name, nil
		}
	}

	return false, "", nil
}


func getStorageDevices() ([]map[string]string, error) {
	cmd := exec.Command("lsblk", "-J", "-o", "NAME,MODEL,VENDOR,SIZE,TYPE,SERIAL")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var lsblkOutput struct {
		BlockDevices []BlockDevice `json:"blockdevices"`
	}
	err = json.Unmarshal(output, &lsblkOutput)
	if err != nil {
		return nil, err
	}

	var storages []map[string]string
	for _, device := range lsblkOutput.BlockDevices {
		if device.Type == "disk" {
			storage := make(map[string]string)
			storage["name"] = device.Name
			storage["model"] = device.Model
			storage["vendor"] = device.Vendor
			storage["size"] = device.Size
			storage["serial"] = device.Serial
			storages = append(storages, storage)
		}
	}

	return storages, nil
}


func installIPMITool() error {
	cmd := exec.Command("which", "ipmitool")
	_, err := cmd.Output()
	if err != nil {
		fmt.Println("ipmitool 패키지를 설치합니다.")
		installCmd := exec.Command("sudo", "apt-get", "install", "-y", "ipmitool")
		installOutput, installErr := installCmd.CombinedOutput()
		if installErr != nil {
			return fmt.Errorf("ipmitool 패키지 설치 실패: %v, 상세 정보: %s", installErr, string(installOutput))
		}
		fmt.Println("ipmitool 패키지가 성공적으로 설치되었습니다.")
	}

	return nil
}

func printIPMISystemLogs() error {
	cmd := exec.Command("sudo", "ipmitool", "sel", "elist")
	output, err := cmd.Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("ipmitool 명령이 실패했습니다. IPMI 설정을 확인하십시오")
		}
		return fmt.Errorf("ipmitool 명령 실행 중 오류 발생: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	keywords := []string{"error", "fail", "fault", "critical"}

	logFilePath := "/var/log/ipmi.log"
	var logFileContent string

	if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
		file, err := os.Create(logFilePath)
		if err != nil {
			return fmt.Errorf("파일 생성 중 오류 발생: %v", err)
		}
		file.Close()
	} else {
		contentBytes, err := ioutil.ReadFile(logFilePath)
		if err != nil {
			return fmt.Errorf("파일 읽기 중 오류 발생: %v", err)
		}
		logFileContent = string(contentBytes)
	}

	var newLogContent string
	for _, line := range lines {
		lowerLine := strings.ToLower(line)
		for _, keyword := range keywords {
			if strings.Contains(lowerLine, keyword) {
				newLogContent += line + "\n"
				break
			}
		}
	}

	if logFileContent != newLogContent {
		err := ioutil.WriteFile(logFilePath, []byte(newLogContent), 0644)
		if err != nil {
			return fmt.Errorf("파일 쓰기 중 오류 발생: %v", err)
		}
	}

	return nil
}

func searchOrCreateDevice(netboxClient *netbox.Netbox, domainName string) (int64, error) {
	// 도메인 이름으로 Devices 검색
	deviceID, err := searchDevice(netboxClient, domainName)
	if err != nil {
		return 0, err
	}

	// Devices가 없으면 생성
	if deviceID == 0 {
		deviceID, err = createDevice(netboxClient, domainName)
		if err != nil {
			return 0, err
		}
	}

	return deviceID, nil
}

func searchDevice(netboxClient *netbox.Netbox, domainName string) (int64, error) {
	// 기존 코드...

	// 도메인 이름으로 Devices 검색하는 코드를 여기에 추가하세요.
	params := dcim.NewDcimDevicesListParams().WithName(&domainName)
	resp, err := netboxClient.Dcim.DcimDevicesList(params, nil)

	if err != nil {
		return 0, fmt.Errorf("failed to search device: %v", err)
	}

	if len(resp.Payload.Results) > 0 {
		return resp.Payload.Results[0].ID, nil
	}

	return 0, nil

}

func createDevice(netboxClient *netbox.Netbox, domainName string) (int64, error) {
	// 기존 코드...

	// 도메인 이름으로 Devices 생성하는 코드를 여기에 추가하세요.
	roleID, err := createOrGetDeviceRoleID(netboxClient, deviceRole)
	if err != nil {
		return 0, err
	}

	// Device Type 생성 및 검색
	typeID, err := createOrGetDeviceTypeID(netboxClient, productName, manufacturer)
	if err != nil {
		return 0, err
	}

	// Site 생성 및 검색
	siteID, err := createOrGetSiteID(netboxClient, site)
	if err != nil {
		return 0, err
	}

	// Platform 생성 및 검색
	platformID, err := createOrGetPlatformID(netboxClient, platform)
	if err != nil {
		return 0, err
	}

	// Device 생성
	deviceParams := dcim.NewDcimDevicesCreateParams().WithData(&models.WritableDevice{
		Name:         domainName,
		DeviceRole:   roleID,
		DeviceType:   typeID,
		Serial:       serialNumber,
		Site:         siteID,
		Platform:     platformID,
	})
	resp, err := netboxClient.Dcim.DcimDevicesCreate(deviceParams, nil)

	if err != nil {
		return 0, fmt.Errorf("failed to create device: %v", err)
	}

	return resp.Payload.ID, nil
}

func addComponents(netboxClient *netbox.Netbox, deviceID int64) error {
	// Components 추가 코드를 여기에 추가하세요.

	// Module bays 추가
	err := addModuleBays(netboxClient, deviceID)
	if err != nil {
		return err
	}

	// Interfaces 추가
	err = addInterfaces(netboxClient, deviceID)
	if err != nil {
		return err
	}

	return nil
}


func addModuleBays(netboxClient *netbox.Netbox, deviceID int64) error {
	moduleBayNames := []string{"GPU", "NIC", "Storage"}

	for _, moduleName := range moduleBayNames {
		// Module Type 생성 및 검색
		moduleTypeID, err := createOrGetModuleTypeID(netboxClient, moduleName, manufacturer)
		if err != nil {
			return err
		}

		// Module Bay 생성
		moduleBayParams := dcim.NewDcimDeviceBaysCreateParams().WithData(&models.WritableDeviceBay{
			Device:   deviceID,
			Name:     moduleName,
			Type:     moduleTypeID,
		})
		_, err = netboxClient.Dcim.DcimDeviceBaysCreate(moduleBayParams, nil)

		if err != nil {
			return fmt.Errorf("failed to create module bay: %v", err)
		}
	}

	return nil
}

func addInterfaces(netboxClient *netbox.Netbox, deviceID int64) error {
	for _, nic := range nics {
		// Interface 생성
		interfaceParams := dcim.NewDcimInterfacesCreateParams().WithData(&models.WritableInterface{
			Device:     deviceID,
			Name:       nic.Name,
			Type:       interfaceType,
			MACAddress: nic.MACAddress,
		})
		_, err := netboxClient.Dcim.DcimInterfacesCreate(interfaceParams, nil)

		if err != nil {
			return fmt.Errorf("failed to create interface: %v", err)
		}
	}

	return nil
}
