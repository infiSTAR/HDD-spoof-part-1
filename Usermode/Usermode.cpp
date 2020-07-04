// Us// get_serial_number.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>

using namespace std;


int main()
{
    std::wstring path = L"\\\\.\\PhysicalDrive0";
    HANDLE  diskHandle = CreateFile2(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, OPEN_EXISTING, NULL);

    STORAGE_PROPERTY_QUERY requestStruct;
    requestStruct.PropertyId = StorageDeviceProperty;
    requestStruct.QueryType = PropertyStandardQuery;

    STORAGE_DESCRIPTOR_HEADER storageDescriptorHeader;
    DWORD  dwBytesReturned;

    DeviceIoControl(diskHandle, IOCTL_STORAGE_QUERY_PROPERTY, &requestStruct, sizeof(STORAGE_PROPERTY_QUERY), &storageDescriptorHeader, sizeof(STORAGE_DESCRIPTOR_HEADER),
        &dwBytesReturned, NULL); //get size of storage descriptor first

    DWORD outBufferSize = storageDescriptorHeader.Size;

    BYTE* pOutBuffer = new BYTE[outBufferSize];



    DeviceIoControl(diskHandle, IOCTL_STORAGE_QUERY_PROPERTY,
        &requestStruct, sizeof(STORAGE_PROPERTY_QUERY),
        pOutBuffer, outBufferSize,
        &dwBytesReturned, NULL);

    // Now, the output buffer points to a buffer containing STORAGE_DEVICE_DESCRIPTOR structure
    // followed by additional info like vendor ID, product ID, serial number, and so on.
    STORAGE_DEVICE_DESCRIPTOR* pDeviceDescriptor = (STORAGE_DEVICE_DESCRIPTOR*)pOutBuffer;


    cout << "serial number offset is: " << pDeviceDescriptor->SerialNumberOffset << endl;
    cout << "your serial number is:" << pOutBuffer + pDeviceDescriptor->SerialNumberOffset << endl;
    int a;
    while (1)
    {

        std::cout << "enter 1 to exit, : \n" << endl;
        std::cin >> a;
        if (a == 1)
        {
            break;
        }
    }
    return 0;
}

