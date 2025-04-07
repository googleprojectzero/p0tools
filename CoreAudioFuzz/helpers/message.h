/* 
Copyright 2025 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef MESSAGE_H
#define MESSAGE_H

#include <iostream>
#include <set>

typedef enum {
    XSystem_Open = 1010000,
    XSystem_Close = 1010001,
    XSystem_GetObjectInfo = 1010002,
    XSystem_CreateIOContext = 1010003,
    XSystem_DestroyIOContext = 1010004,
    XSystem_CreateMetaDevice = 1010005,
    XSystem_DestroyMetaDevice = 1010006,
    XSystem_ReadSetting = 1010007,
    XSystem_WriteSetting = 1010008,
    XSystem_DeleteSetting = 1010009,
    XIOContext_SetClientControlPort = 1010010,
    XIOContext_Start = 1010011,
    XIOContext_Stop = 1010012,
    XObject_HasProperty = 1010013,
    XObject_IsPropertySettable = 1010014,
    XObject_GetPropertyData = 1010015,
    XObject_GetPropertyData_DI32 = 1010016,
    XObject_GetPropertyData_DI32_QI32 = 1010017,
    XObject_GetPropertyData_DI32_QCFString = 1010018,
    XObject_GetPropertyData_DAI32 = 1010019,
    XObject_GetPropertyData_DAI32_QAI32 = 1010020,
    XObject_GetPropertyData_DCFString = 1010021,
    XObject_GetPropertyData_DCFString_QI32 = 1010022,
    XObject_GetPropertyData_DF32 = 1010023,
    XObject_GetPropertyData_DF32_QF32 = 1010024,
    XObject_GetPropertyData_DF64 = 1010025,
    XObject_GetPropertyData_DAF64 = 1010026,
    XObject_GetPropertyData_DPList = 1010027,
    XObject_GetPropertyData_DCFURL = 1010028,
    XObject_SetPropertyData = 1010029,
    XObject_SetPropertyData_DI32 = 1010030,
    XObject_SetPropertyData_DF32 = 1010031,
    XObject_SetPropertyData_DF64 = 1010032,
    XObject_SetPropertyData_DCFString = 1010033,
    XObject_SetPropertyData_DPList = 1010034,
    XObject_AddPropertyListener = 1010035,
    XObject_RemovePropertyListener = 1010036,
    XSystem_OpenWithBundleID = 1010037,
    XTransportManager_CreateDevice = 1010038,
    XTransportManager_DestroyDevice = 1010039,
    XObject_GetPropertyData_DCFString_QRaw = 1010040,
    XObject_GetPropertyData_DCFString_QCFString = 1010041,
    XObject_GetPropertyData_DCFString_QPList = 1010042,
    XObject_GetPropertyData_DPList_QRaw = 1010043,
    XObject_GetPropertyData_DPList_QCFString = 1010044,
    XObject_GetPropertyData_DPList_QPList = 1010045,
    XObject_SetPropertyData_DAI32 = 1010046,
    XObject_SetPropertyData_DCFString_QRaw = 1010047,
    XObject_SetPropertyData_DCFString_QCFString = 1010048,
    XObject_SetPropertyData_DCFString_QPList = 1010049,
    XObject_SetPropertyData_DPList_QRaw = 1010050,
    XObject_SetPropertyData_DPList_QCFString = 1010051,
    XObject_SetPropertyData_DPList_QPList = 1010052,
    XSystem_OpenWithBundleIDAndLinkage = 1010053,
    XIOContext_StartAtTime = 1010054,
    XObject_GetPropertyData_DAI64 = 1010055,
    XObject_GetPropertyData_DAI64_QAI64 = 1010056,
    XObject_SetPropertyData_DAI64 = 1010057,
    XIOContext_Start_With_WorkInterval = 1010058,
    XIOContext_Fetch_Workgroup_Port = 1010059,
    XSystem_OpenWithBundleIDLinkageAndKind = 1010060,
    XSystem_OpenWithBundleIDLinkageAndKindAndSynchronousGroupProperties = 1010061,
    XSystem_OpenWithBundleIDLinkageAndKindAndShmem = 1010062,
    XIOContext_Start_Shmem = 1010063,
    XIOContext_StartAtTime_Shmem = 1010064,
    XIOContext_Start_With_WorkInterval_Shmem = 1010065,
    XSystem_OpenWithBundleIDLinkageAndKindAndSynchronousGroupPropertiesAndShmem = 1010066,
    XIOContext_WaitForTap = 1010067,
    XIOContext_StopWaitingForTap = 1010068,
    XIOContext_Start_With_Shmem_SemaphoreTimeout = 1010069,
    XIOContext_StartAtTime_With_Shmem_SemaphoreTimeout = 1010070,
    XSystem_OpenWithBundleIDLinkageAndKindAndSynchronousGroupPropertiesAndShmemAndTimeout = 1010071
} message_id_enum;

extern std::set<message_id_enum> ool_descriptor_set;
extern const char* message_id_to_string(message_id_enum msg_id);

#endif // MESSAGE_H