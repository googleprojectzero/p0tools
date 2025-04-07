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

#include "message_ids.h"

const char* message_id_to_string(message_id_enum msg_id) {
    switch (msg_id) {
        case XSystem_Open: return "XSystem_Open";
        case XSystem_Close: return "XSystem_Close";
        case XSystem_GetObjectInfo: return "XSystem_GetObjectInfo";
        case XSystem_CreateIOContext: return "XSystem_CreateIOContext";
        case XSystem_DestroyIOContext: return "XSystem_DestroyIOContext";
        case XSystem_CreateMetaDevice: return "XSystem_CreateMetaDevice";
        case XSystem_DestroyMetaDevice: return "XSystem_DestroyMetaDevice";
        case XSystem_ReadSetting: return "XSystem_ReadSetting";
        case XSystem_WriteSetting: return "XSystem_WriteSetting";
        case XSystem_DeleteSetting: return "XSystem_DeleteSetting";
        case XIOContext_SetClientControlPort: return "XIOContext_SetClientControlPort";
        case XIOContext_Start: return "XIOContext_Start";
        case XIOContext_Stop: return "XIOContext_Stop";
        case XObject_HasProperty: return "XObject_HasProperty";
        case XObject_IsPropertySettable: return "XObject_IsPropertySettable";
        case XObject_GetPropertyData: return "XObject_GetPropertyData";
        case XObject_GetPropertyData_DI32: return "XObject_GetPropertyData_DI32";
        case XObject_GetPropertyData_DI32_QI32: return "XObject_GetPropertyData_DI32_QI32";
        case XObject_GetPropertyData_DI32_QCFString: return "XObject_GetPropertyData_DI32_QCFString";
        case XObject_GetPropertyData_DAI32: return "XObject_GetPropertyData_DAI32";
        case XObject_GetPropertyData_DAI32_QAI32: return "XObject_GetPropertyData_DAI32_QAI32";
        case XObject_GetPropertyData_DCFString: return "XObject_GetPropertyData_DCFString";
        case XObject_GetPropertyData_DCFString_QI32: return "XObject_GetPropertyData_DCFString_QI32";
        case XObject_GetPropertyData_DF32: return "XObject_GetPropertyData_DF32";
        case XObject_GetPropertyData_DF32_QF32: return "XObject_GetPropertyData_DF32_QF32";
        case XObject_GetPropertyData_DF64: return "XObject_GetPropertyData_DF64";
        case XObject_GetPropertyData_DAF64: return "XObject_GetPropertyData_DAF64";
        case XObject_GetPropertyData_DPList: return "XObject_GetPropertyData_DPList";
        case XObject_GetPropertyData_DCFURL: return "XObject_GetPropertyData_DCFURL";
        case XObject_SetPropertyData: return "XObject_SetPropertyData";
        case XObject_SetPropertyData_DI32: return "XObject_SetPropertyData_DI32";
        case XObject_SetPropertyData_DF32: return "XObject_SetPropertyData_DF32";
        case XObject_SetPropertyData_DF64: return "XObject_SetPropertyData_DF64";
        case XObject_SetPropertyData_DCFString: return "XObject_SetPropertyData_DCFString";
        case XObject_SetPropertyData_DPList: return "XObject_SetPropertyData_DPList";
        case XObject_AddPropertyListener: return "XObject_AddPropertyListener";
        case XObject_RemovePropertyListener: return "XObject_RemovePropertyListener";
        case XSystem_OpenWithBundleID: return "XSystem_OpenWithBundleID";
        case XTransportManager_CreateDevice: return "XTransportManager_CreateDevice";
        case XTransportManager_DestroyDevice: return "XTransportManager_DestroyDevice";
        case XObject_GetPropertyData_DCFString_QRaw: return "XObject_GetPropertyData_DCFString_QRaw";
        case XObject_GetPropertyData_DCFString_QCFString: return "XObject_GetPropertyData_DCFString_QCFString";
        case XObject_GetPropertyData_DCFString_QPList: return "XObject_GetPropertyData_DCFString_QPList";
        case XObject_GetPropertyData_DPList_QRaw: return "XObject_GetPropertyData_DPList_QRaw";
        case XObject_GetPropertyData_DPList_QCFString: return "XObject_GetPropertyData_DPList_QCFString";
        case XObject_GetPropertyData_DPList_QPList: return "XObject_GetPropertyData_DPList_QPList";
        case XObject_SetPropertyData_DAI32: return "XObject_SetPropertyData_DAI32";
        case XObject_SetPropertyData_DCFString_QRaw: return "XObject_SetPropertyData_DCFString_QRaw";
        case XObject_SetPropertyData_DCFString_QCFString: return "XObject_SetPropertyData_DCFString_QCFString";
        case XObject_SetPropertyData_DCFString_QPList: return "XObject_SetPropertyData_DCFString_QPList";
        case XObject_SetPropertyData_DPList_QRaw: return "XObject_SetPropertyData_DPList_QRaw";
        case XObject_SetPropertyData_DPList_QCFString: return "XObject_SetPropertyData_DPList_QCFString";
        case XObject_SetPropertyData_DPList_QPList: return "XObject_SetPropertyData_DPList_QPList";
        case XSystem_OpenWithBundleIDAndLinkage: return "XSystem_OpenWithBundleIDAndLinkage";
        case XIOContext_StartAtTime: return "XIOContext_StartAtTime";
        case XObject_GetPropertyData_DAI64: return "XObject_GetPropertyData_DAI64";
        case XObject_GetPropertyData_DAI64_QAI64: return "XObject_GetPropertyData_DAI64_QAI64";
        case XObject_SetPropertyData_DAI64: return "XObject_SetPropertyData_DAI64";
        case XIOContext_Start_With_WorkInterval: return "XIOContext_Start_With_WorkInterval";
        case XIOContext_Fetch_Workgroup_Port: return "XIOContext_Fetch_Workgroup_Port";
        case XSystem_OpenWithBundleIDLinkageAndKind: return "XSystem_OpenWithBundleIDLinkageAndKind";
        case XSystem_OpenWithBundleIDLinkageAndKindAndSynchronousGroupProperties: return "XSystem_OpenWithBundleIDLinkageAndKindAndSynchronousGroupProperties";
        default: return "Unknown Message ID";
    }
}