// +build windows,amd64

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// =============================================================================
// Trampoline-based API Hooking
// =============================================================================

const (
	jumpLength = 14 // Length of our JMP patch
)

// Hook holds all the information for a single API hook.
type Hook struct {
	target      *windows.LazyProc
	detour      uintptr
	trampoline  uintptr
	originalBytes []byte
}

var hooks = make(map[string]*Hook)

// installHook creates a trampoline and installs a detour.
func installHook(name string, target *windows.LazyProc, detour uintptr) (*Hook, error) {
	if err := target.Load(); err != nil {
		return nil, fmt.Errorf("failed to load target procedure %s: %w", name, err)
	}
	address := target.Addr()

	hook := &Hook{
		target:      target,
		detour:      detour,
		originalBytes: make([]byte, jumpLength),
	}

	// 1. Save original bytes.
	copy(hook.originalBytes, unsafe.Slice((*byte)(unsafe.Pointer(address)), jumpLength))

	// 2. Create trampoline.
	trampoline, err := windows.VirtualAlloc(0, uintptr(jumpLength*2), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("VirtualAlloc for trampoline failed: %w", err)
	}
	hook.trampoline = trampoline

	trampolineSlice := unsafe.Slice((*byte)(unsafe.Pointer(trampoline)), jumpLength*2)
	
	// 3. Write original bytes to trampoline.
	copy(trampolineSlice, hook.originalBytes)

	// 4. Write jump back instruction from trampoline to original function.
	jumpBackAddress := address + uintptr(jumpLength)
	jumpBackInstruction := make([]byte, jumpLength)
	copy(jumpBackInstruction, []byte{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00}) // JMP [rip+0]
	binary.LittleEndian.PutUint64(jumpBackInstruction[6:], uint64(jumpBackAddress))
	copy(trampolineSlice[jumpLength:], jumpBackInstruction)

	// 5. Create patch to jump from original function to our detour.
	patch := make([]byte, jumpLength)
	copy(patch, []byte{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00}) // JMP [rip+0]
	binary.LittleEndian.PutUint64(patch[6:], uint64(detour))

	// 6. Apply the patch.
	var oldProtect uint32
	if err := windows.VirtualProtect(address, uintptr(jumpLength), windows.PAGE_EXECUTE_READWRITE, &oldProtect); err != nil {
		windows.VirtualFree(trampoline, 0, windows.MEM_RELEASE)
		return nil, fmt.Errorf("VirtualProtect (write) failed for %s: %w", name, err)
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(address)), jumpLength), patch)
	if err := windows.VirtualProtect(address, uintptr(jumpLength), oldProtect, &oldProtect); err != nil {
		// Try to revert, but we're in a bad state.
		copy(unsafe.Slice((*byte)(unsafe.Pointer(address)), jumpLength), hook.originalBytes)
		windows.VirtualFree(trampoline, 0, windows.MEM_RELEASE)
		return nil, fmt.Errorf("VirtualProtect (restore) failed for %s: %w", name, err)
	}

	hooks[name] = hook
	return hook, nil
}

func unhook(name string) error {
	hook, ok := hooks[name]
	if !ok {
		return fmt.Errorf("hook %s not found", name)
	}
	address := hook.target.Addr()

	var oldProtect uint32
	if err := windows.VirtualProtect(address, uintptr(len(hook.originalBytes)), windows.PAGE_EXECUTE_READWRITE, &oldProtect); err != nil {
		return fmt.Errorf("VirtualProtect (write) during unhook for %s failed: %w", name, err)
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(address)), len(hook.originalBytes)), hook.originalBytes)
	if err := windows.VirtualProtect(address, uintptr(len(hook.originalBytes)), oldProtect, &oldProtect); err != nil {
		return fmt.Errorf("VirtualProtect (restore) during unhook for %s failed: %w", name, err)
	}
	if err := windows.VirtualFree(hook.trampoline, 0, windows.MEM_RELEASE); err != nil {
		return fmt.Errorf("VirtualFree for trampoline failed for %s: %w", name, err)
	}
	delete(hooks, name)
	return nil
}

// =============================================================================
// SMBIOS Structures
// =============================================================================

type RawSMBIOSData struct {
	Used20CallingMethod uint8
	SMBIOSMajorVersion  uint8
	SMBIOSMinorVersion  uint8
	DmiRevision         uint8
	Length              uint32
}
type SMBIOSHeader struct {
	Type   uint8
	Length uint8
	Handle uint16
}

// --- Type 0 ---
type SMBIOSType0 struct {
	Header       SMBIOSType0_formatted
	VendorStr      string `json:"vendor"`
	BIOSVersionStr string `json:"bios_version"`
	ReleaseDateStr string `json:"release_date"`
}
type SMBIOSType0_formatted struct {
	Header                     SMBIOSHeader
	Vendor                     uint8
	BIOSVersion                uint8
	BIOSStartingAddressSegment uint16
	BIOSReleaseDate            uint8
	BIOSROMSize                uint8
	BIOSCharacteristics        uint64
	BIOSCharacteristicsExtension [2]uint8
	SystemBIOSMajorRelease     uint8
	SystemBIOSMinorRelease     uint8
	ECFirmwareMajorRelease     uint8
	ECFirmwareMinorRelease     uint8
}

// --- Type 1 ---
type SMBIOSType1 struct {
	Header          SMBIOSType1_formatted
	ManufacturerStr string `json:"manufacturer"`
	ProductNameStr  string `json:"product_name"`
	VersionStr      string `json:"version"`
	SerialNumberStr string `json:"serial_number"`
}
type SMBIOSType1_formatted struct {
	Header       SMBIOSHeader
	Manufacturer uint8
	ProductName  uint8
	Version      uint8
	SerialNumber uint8
	UUID [16]uint8 `json:"uuid"`
	WakeUpType   uint8   `json:"wake_up_type"`
	SKUNumber    uint8
	Family       uint8
}

// --- Type 2 ---
type SMBIOSType2 struct {
	Header               SMBIOSType2_formatted
	ManufacturerStr      string `json:"manufacturer"`
	ProductStr           string `json:"product"`
	VersionStr           string `json:"version"`
	SerialNumberStr      string `json:"serial_number"`
	AssetTagStr          string `json:"asset_tag"`
	LocationInChassisStr string `json:"location_in_chassis"`
}
type SMBIOSType2_formatted struct {
	Header                        SMBIOSHeader
	Manufacturer                  uint8
	Product                       uint8
	Version                       uint8
	SerialNumber                  uint8
	AssetTag                      uint8
	FeatureFlags                  uint8
	LocationInChassis             uint8
	ChassisHandle                 uint16
	BoardType                     uint8
	NumberOfContainedObjectHandles uint8
}

// --- Type 3 ---
type SMBIOSType3 struct {
	Header          SMBIOSType3_formatted
	ManufacturerStr string `json:"manufacturer"`
	VersionStr      string `json:"version"`
	SerialNumberStr string `json:"serial_number"`
	AssetTagStr     string `json:"asset_tag"`
}
type SMBIOSType3_formatted struct {
	Header             SMBIOSHeader
	Manufacturer       uint8
	Type               uint8
	Version            uint8
	SerialNumber       uint8
	AssetTag           uint8
	BootUpState        uint8
	PowerSupplyState   uint8
	ThermalState       uint8
	SecurityStatus     uint8
	OEMDefined         uint32
	Height             uint8
	NumberOfPowerCords uint8
}

type GenericSMBIOSTable struct {
	Header  SMBIOSHeader
	RawData []byte
	Strings []string
}
type SMBIOSData struct {
	Version       string `json:"version"`
	BIOSInfo []SMBIOSType0
	SystemInfo []SMBIOSType1
	BaseboardInfo []SMBIOSType2
	ChassisInfo []SMBIOSType3
	OtherTables []GenericSMBIOSTable
}

// =============================================================================
// Disk Spoofing Structures
// =============================================================================
const (
	IOCTL_STORAGE_QUERY_PROPERTY = 0x2D1400
	StorageDeviceProperty        = 0
)

type STORAGE_PROPERTY_QUERY struct {
	PropertyId             uint32
	QueryType              uint32
	AdditionalParameters   byte
}

type STORAGE_DEVICE_DESCRIPTOR struct {
	Version               uint32
	Size                  uint32
	DeviceType            uint8
	DeviceTypeModifier    uint8
	RemovableMedia        bool
	CommandQueueing       bool
	VendorIdOffset        uint32
	ProductIdOffset       uint32
	ProductRevisionOffset uint32
	SerialNumberOffset    uint32
	BusType               uint16
	RawPropertiesLength   uint32
	RawDeviceProperties   [1]byte
}

// =============================================================================
// API and Parsing Logic
// =============================================================================

var (
	ntdll                          = windows.NewLazySystemDLL("ntdll.dll")
	procGetSystemFirmwareTable     = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetSystemFirmwareTable")
	procNtDeviceIoControlFile      = ntdll.NewProc("NtDeviceIoControlFile")
	interceptedIoControlEvents     []string
	interceptedIoControlEventsMutex = &sync.Mutex{}
)

const firmwareTableProviderRSMB uint32 = 0x52534D42

// getRawSystemFirmwareTable reads the SMBIOS table using the original, unhooked function.
func getRawSystemFirmwareTable() ([]byte, error) {
	if err := procGetSystemFirmwareTable.Load(); err != nil {
		return nil, err
	}
	size, _, err := procGetSystemFirmwareTable.Call(uintptr(firmwareTableProviderRSMB), 0, 0, 0)
	if size == 0 {
		return nil, fmt.Errorf("GetSystemFirmwareTable (size query) failed: %v", err)
	}
	buffer := make([]byte, size)
	ret, _, err := procGetSystemFirmwareTable.Call(uintptr(firmwareTableProviderRSMB), 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(size))
	if ret == 0 {
		return nil, fmt.Errorf("GetSystemFirmwareTable (data retrieval) failed: %v", err)
	}
	return buffer, nil
}


func getString(strings []string, index uint8) string {
	if index == 0 || int(index) > len(strings) {
		return ""
	}
	return strings[index-1]
}

func extractStrings(tableData []byte, offset int, structLength int) ([]string, int) {
	strings := []string{}
	strStart := offset + int(structLength)
	if strStart >= len(tableData) {
		return strings, strStart
	}

	endOfStrings := strStart
	for endOfStrings+1 < len(tableData) {
		if tableData[endOfStrings] == 0 && tableData[endOfStrings+1] == 0 {
			break
		}
		endOfStrings++
	}
	
	nextTableOffset := endOfStrings + 2

	current := strStart
	for current < endOfStrings {
		end := current
		for end < endOfStrings && tableData[end] != 0 {
			end++
		}
		if end > current {
			strings = append(strings, string(tableData[current:end]))
		}
		current = end + 1
	}

	return strings, nextTableOffset
}


func parseSMBIOSTables(rawData []byte) (*SMBIOSData, error) {
	if len(rawData) < 8 {
		return nil, fmt.Errorf("SMBIOS data too short")
	}
	header := RawSMBIOSData{
		SMBIOSMajorVersion: rawData[1],
		SMBIOSMinorVersion: rawData[2],
		Length:             binary.LittleEndian.Uint32(rawData[4:8]),
	}
	result := &SMBIOSData{
		Version: fmt.Sprintf("%d.%d", header.SMBIOSMajorVersion, header.SMBIOSMinorVersion),
	}
	tableData := rawData[8:]
	offset := 0
	for offset < len(tableData)-1 {
		if offset+4 > len(tableData) {
			break
		}
		structType := tableData[offset]
		structLength := tableData[offset+1]
		if structType == 127 {
			break
		}
		if structLength < 4 {
			offset++
			continue
		}
		if offset+int(structLength) > len(tableData) {
			break
		}

		strings, nextOffset := extractStrings(tableData, offset, int(structLength))
		structData := tableData[offset : offset+int(structLength)]
		switch structType {
		case 0:
			var entry SMBIOSType0
			binary.Read(bytes.NewReader(structData), binary.LittleEndian, &entry.Header)
			entry.VendorStr = getString(strings, entry.Header.Vendor)
			entry.BIOSVersionStr = getString(strings, entry.Header.BIOSVersion)
			entry.ReleaseDateStr = getString(strings, entry.Header.BIOSReleaseDate)
			result.BIOSInfo = append(result.BIOSInfo, entry)
		case 1:
			var entry SMBIOSType1
			binary.Read(bytes.NewReader(structData), binary.LittleEndian, &entry.Header)
			entry.ManufacturerStr = getString(strings, entry.Header.Manufacturer)
			entry.ProductNameStr = getString(strings, entry.Header.ProductName)
			entry.VersionStr = getString(strings, entry.Header.Version)
			entry.SerialNumberStr = getString(strings, entry.Header.SerialNumber)
			result.SystemInfo = append(result.SystemInfo, entry)
		case 2:
			var entry SMBIOSType2
			binary.Read(bytes.NewReader(structData), binary.LittleEndian, &entry.Header)
			entry.ManufacturerStr = getString(strings, entry.Header.Manufacturer)
			entry.ProductStr = getString(strings, entry.Header.Product)
			entry.VersionStr = getString(strings, entry.Header.Version)
			entry.SerialNumberStr = getString(strings, entry.Header.SerialNumber)
			entry.AssetTagStr = getString(strings, entry.Header.AssetTag)
			entry.LocationInChassisStr = getString(strings, entry.Header.LocationInChassis)
			result.BaseboardInfo = append(result.BaseboardInfo, entry)
		case 3:
			var entry SMBIOSType3
			binary.Read(bytes.NewReader(structData), binary.LittleEndian, &entry.Header)
			entry.ManufacturerStr = getString(strings, entry.Header.Manufacturer)
			entry.VersionStr = getString(strings, entry.Header.Version)
			entry.SerialNumberStr = getString(strings, entry.Header.SerialNumber)
			entry.AssetTagStr = getString(strings, entry.Header.AssetTag)
			result.ChassisInfo = append(result.ChassisInfo, entry)
		default:
			generic := GenericSMBIOSTable{
				Header: SMBIOSHeader{
					Type:   structType,
					Length: structLength,
					Handle: binary.LittleEndian.Uint16(structData[2:4]),
				},
				RawData: structData[4:],
				Strings: strings,
			}
			result.OtherTables = append(result.OtherTables, generic)
		}
		offset = nextOffset
	}
	return result, nil
}

// =============================================================================
// Re-serialization Logic
// =============================================================================
type smbiosWriter struct {
	strings []string
	buffer  bytes.Buffer
}

func (w *smbiosWriter) addString(s string) uint8 {
	if s == "" {
		return 0
	}
	for i, existing := range w.strings {
		if existing == s {
			return uint8(i + 1)
		}
	}
	w.strings = append(w.strings, s)
	return uint8(len(w.strings))
}
func (w *smbiosWriter) writeStrings() {
	if len(w.strings) > 0 {
		for _, s := range w.strings {
			w.buffer.WriteString(s)
			w.buffer.WriteByte(0)
		}
	}
	w.buffer.WriteByte(0)
	w.buffer.WriteByte(0)
}

func reserializeTable(table interface{}) ([]byte, error) {
	writer := smbiosWriter{}
	var formattedPart interface{}

	switch t := table.(type) {
	case *SMBIOSType0:
		t.Header.Vendor = writer.addString(t.VendorStr)
		t.Header.BIOSVersion = writer.addString(t.BIOSVersionStr)
		t.Header.BIOSReleaseDate = writer.addString(t.ReleaseDateStr)
		formattedPart = &t.Header
	case *SMBIOSType1:
		t.Header.Manufacturer = writer.addString(t.ManufacturerStr)
		t.Header.ProductName = writer.addString(t.ProductNameStr)
		t.Header.Version = writer.addString(t.VersionStr)
		t.Header.SerialNumber = writer.addString(t.SerialNumberStr)
		formattedPart = &t.Header
	case *SMBIOSType2:
		t.Header.Manufacturer = writer.addString(t.ManufacturerStr)
		t.Header.Product = writer.addString(t.ProductStr)
		t.Header.Version = writer.addString(t.VersionStr)
		t.Header.SerialNumber = writer.addString(t.SerialNumberStr)
		t.Header.AssetTag = writer.addString(t.AssetTagStr)
		t.Header.LocationInChassis = writer.addString(t.LocationInChassisStr)
		formattedPart = &t.Header
	case *SMBIOSType3:
		t.Header.Manufacturer = writer.addString(t.ManufacturerStr)
		t.Header.Version = writer.addString(t.VersionStr)
		t.Header.SerialNumber = writer.addString(t.SerialNumberStr)
		t.Header.AssetTag = writer.addString(t.AssetTagStr)
		formattedPart = &t.Header
	default:
		return nil, fmt.Errorf("unsupported table type for re-serialization")
	}

	err := binary.Write(&writer.buffer, binary.LittleEndian, formattedPart)
	if err != nil {
		return nil, fmt.Errorf("failed to write struct: %w", err)
	}
	writer.writeStrings()
	return writer.buffer.Bytes(), nil
}

func reserializeSMBIOSTables(data *SMBIOSData) ([]byte, error) {
	var finalBuffer bytes.Buffer
	for i := range data.BIOSInfo {
		table, err := reserializeTable(&data.BIOSInfo[i])
		if err != nil {
			return nil, err
		}
		finalBuffer.Write(table)
	}
	for i := range data.SystemInfo {
		table, err := reserializeTable(&data.SystemInfo[i])
		if err != nil {
			return nil, err
		}
		finalBuffer.Write(table)
	}
	for i := range data.BaseboardInfo {
		table, err := reserializeTable(&data.BaseboardInfo[i])
		if err != nil {
			return nil, err
		}
		finalBuffer.Write(table)
	}
	for i := range data.ChassisInfo {
		table, err := reserializeTable(&data.ChassisInfo[i])
		if err != nil {
			return nil, err
		}
		finalBuffer.Write(table)
	}
	for _, table := range data.OtherTables {
		headerBytes := new(bytes.Buffer)
		binary.Write(headerBytes, binary.LittleEndian, &table.Header)
		finalBuffer.Write(headerBytes.Bytes())
		finalBuffer.Write(table.RawData)
		stringWriter := smbiosWriter{}
		for _, s := range table.Strings {
			stringWriter.addString(s)
		}
		stringWriter.writeStrings()
		finalBuffer.Write(stringWriter.buffer.Bytes())
	}
	endOfTables := SMBIOSHeader{Type: 127, Length: 4, Handle: 0xFFFF}
	binary.Write(&finalBuffer, binary.LittleEndian, &endOfTables)
	finalBuffer.Write([]byte{0, 0})
	rawSMBIOSHeader := RawSMBIOSData{
		SMBIOSMajorVersion: data.BIOSInfo[0].Header.SystemBIOSMajorRelease,
		SMBIOSMinorVersion: data.BIOSInfo[0].Header.SystemBIOSMinorRelease,
		Length:             uint32(finalBuffer.Len()),
	}
	headerBuf := new(bytes.Buffer)
	binary.Write(headerBuf, binary.LittleEndian, rawSMBIOSHeader)
	return append(headerBuf.Bytes(), finalBuffer.Bytes()...), nil
}


// =============================================================================
// Hooking Logic
// =============================================================================

var spoofedSMBIOSTable []byte

func callTrampoline(name string, args ...uintptr) (uintptr, error) {
	hook, ok := hooks[name]
	if !ok {
		return 0, fmt.Errorf("hook %s not found", name)
	}
	
	switch len(args) {
	case 4: // GetSystemFirmwareTable
		ret, _, _ := syscall.Syscall6(hook.trampoline, uintptr(len(args)), args[0], args[1], args[2], args[3], 0, 0)
		return ret, nil
	case 10: // NtDeviceIoControlFile
		ret, _, _ := syscall.Syscall12(hook.trampoline, uintptr(len(args)), args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], 0, 0)
		return ret, nil
	default:
		return 0, fmt.Errorf("unsupported number of arguments: %d", len(args))
	}
}


func detourGetSystemFirmwareTable(provider uint32, id uint32, buffer uintptr, size uint32) uintptr {
	if provider != firmwareTableProviderRSMB {
		ret, _ := callTrampoline("GetSystemFirmwareTable", uintptr(provider), uintptr(id), buffer, uintptr(size))
		return ret
	}

	interceptedIoControlEventsMutex.Lock()
	interceptedIoControlEvents = append(interceptedIoControlEvents, "[HOOK] GetSystemFirmwareTable: Intercepted SMBIOS call.")
	interceptedIoControlEventsMutex.Unlock()

	spoofedSize := uint32(len(spoofedSMBIOSTable))
	if buffer == 0 || size < spoofedSize {
		return uintptr(spoofedSize)
	}
	dest := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), size)
	copy(dest, spoofedSMBIOSTable)
	return uintptr(spoofedSize)
}

func detourNtDeviceIoControlFile(FileHandle windows.Handle, Event windows.Handle, ApcRoutine uintptr, ApcContext uintptr, IoStatusBlock uintptr, IoControlCode uint32, InputBuffer uintptr, InputBufferLength uint32, OutputBuffer uintptr, OutputBufferLength uint32) uintptr {
	interceptedIoControlEventsMutex.Lock()
	interceptedIoControlEvents = append(interceptedIoControlEvents, fmt.Sprintf("[HOOK] NtDeviceIoControlFile: Intercepted call with IOCTL=0x%X", IoControlCode))
	interceptedIoControlEventsMutex.Unlock()

	if IoControlCode == IOCTL_STORAGE_QUERY_PROPERTY && InputBuffer != 0 {
		query := (*STORAGE_PROPERTY_QUERY)(unsafe.Pointer(InputBuffer))
		
		interceptedIoControlEventsMutex.Lock()
		interceptedIoControlEvents = append(interceptedIoControlEvents, fmt.Sprintf("[HOOK] NtDeviceIoControlFile: PropertyId=0x%X, QueryType=0x%X", query.PropertyId, query.QueryType))
		interceptedIoControlEventsMutex.Unlock()

		if query.PropertyId == StorageDeviceProperty {
			interceptedIoControlEventsMutex.Lock()
			interceptedIoControlEvents = append(interceptedIoControlEvents, "[HOOK] NtDeviceIoControlFile: Matched IOCTL_STORAGE_QUERY_PROPERTY with StorageDeviceProperty.")
			interceptedIoControlEventsMutex.Unlock()
			
			ret, _ := callTrampoline("NtDeviceIoControlFile", uintptr(FileHandle), uintptr(Event), ApcRoutine, ApcContext, IoStatusBlock, uintptr(IoControlCode), InputBuffer, uintptr(InputBufferLength), OutputBuffer, uintptr(OutputBufferLength))

			if ret == 0 { // STATUS_SUCCESS is 0 for NT functions
				descriptor := (*STORAGE_DEVICE_DESCRIPTOR)(unsafe.Pointer(OutputBuffer))
				if descriptor.SerialNumberOffset > 0 && descriptor.SerialNumberOffset < OutputBufferLength {
					serialNumberPtr := (*byte)(unsafe.Pointer(OutputBuffer + uintptr(descriptor.SerialNumberOffset)))
					serialNumberSlice := unsafe.Slice(serialNumberPtr, OutputBufferLength-descriptor.SerialNumberOffset)
					
					originalSerial := strings.TrimSpace(string(bytes.Trim(serialNumberSlice, "\x00")))
					newSerial := "GO-SPOOFED-DRIVE"
					
					interceptedIoControlEventsMutex.Lock()
					interceptedIoControlEvents = append(interceptedIoControlEvents, fmt.Sprintf("[HOOK] NtDeviceIoControlFile: Original Serial: '%s', Spoofing to: '%s'", originalSerial, newSerial))
					interceptedIoControlEventsMutex.Unlock()

					copy(serialNumberSlice, []byte(newSerial))
					if len(newSerial) < len(serialNumberSlice) {
						serialNumberSlice[len(newSerial)] = 0
					}
				}
			}
			return ret
		}
	}
	ret, _ := callTrampoline("NtDeviceIoControlFile", uintptr(FileHandle), uintptr(Event), ApcRoutine, ApcContext, IoStatusBlock, uintptr(IoControlCode), InputBuffer, uintptr(InputBufferLength), OutputBuffer, uintptr(OutputBufferLength))
	return ret
}

// =============================================================================
// Main Logic
// =============================================================================

func main() {
	fmt.Fprintln(os.Stderr, "Pure Go Hardware Spoofer - Proof-of-Concept")
	fmt.Fprintln(os.Stderr, "==========================================")

	// --- Step 1: Read original data BEFORE hooking ---
	fmt.Fprintln(os.Stderr, "[1] Reading original SMBIOS data...")
	originalRawData, err := getRawSystemFirmwareTable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: Could not get original SMBIOS: %v\n", err)
		os.Exit(1)
	}
	smbiosData, err := parseSMBIOSTables(originalRawData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: Could not parse SMBIOS: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, " -> Successfully parsed %d bytes.\n", len(originalRawData))

	// --- Step 2: Prepare spoofed data ---
	fmt.Fprintln(os.Stderr, "[2] Preparing spoofed data...")
	for i := range smbiosData.SystemInfo {
		smbiosData.SystemInfo[i].SerialNumberStr = "GO-SPOOFED-SYSTEM"
	}
	for i := range smbiosData.BaseboardInfo {
		smbiosData.BaseboardInfo[i].SerialNumberStr = "GO-SPOOFED-BOARD"
	}
	for i := range smbiosData.ChassisInfo {
		smbiosData.ChassisInfo[i].SerialNumberStr = "GO-SPOOFED-CHASSIS"
	}
	
	spoofedSMBIOSTable, err = reserializeSMBIOSTables(smbiosData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: Failed to reserialize spoofed SMBIOS data: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, " -> Spoofed data prepared successfully.")

	// --- Step 3: Install Hooks ---
	fmt.Fprintln(os.Stderr, "[3] Installing API hooks...")
	_, err = installHook("GetSystemFirmwareTable", procGetSystemFirmwareTable, windows.NewCallback(detourGetSystemFirmwareTable))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: Failed to install GetSystemFirmwareTable hook: %v\n", err)
		os.Exit(1)
	}
	defer unhook("GetSystemFirmwareTable")
	fmt.Fprintln(os.Stderr, " -> GetSystemFirmwareTable hook installed.")

	_, err = installHook("NtDeviceIoControlFile", procNtDeviceIoControlFile, windows.NewCallback(detourNtDeviceIoControlFile))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: Failed to install NtDeviceIoControlFile hook: %v\n", err)
		os.Exit(1)
	}
	defer unhook("NtDeviceIoControlFile")
	fmt.Fprintln(os.Stderr, " -> NtDeviceIoControlFile hook installed.")

	// --- Step 4: Wait for user to verify ---
	fmt.Fprintln(os.Stderr, "\n==========================================")
	fmt.Fprintln(os.Stderr, "Spoofing is active.")
	fmt.Fprintln(os.Stderr, "Run a hardware utility (like 'wmic diskdrive get serialnumber') in another terminal to verify.")
	fmt.Fprintln(os.Stderr, "Press ENTER to unhook and exit.")
	fmt.Scanln()

	// --- Step 5: Print intercepted events ---
	fmt.Fprintln(os.Stderr, "\n--- Intercepted Events ---")
	interceptedIoControlEventsMutex.Lock()
	for _, event := range interceptedIoControlEvents {
		fmt.Fprintln(os.Stderr, event)
	}
	interceptedIoControlEventsMutex.Unlock()
}