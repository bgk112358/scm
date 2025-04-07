// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_HANDLER_H
#define CYBERLIB_BUILD_HANDLER_H

#include <string>

namespace cyber {

class Handler {
public:
    Handler();
    ~Handler();

    static Handler *Instance();

    // Container Name
    void SetContainerName(const char *container_name) {
        if (container_name == nullptr) return;
        container_name_ = container_name;
    }
    std::string GetContainerName() { return container_name_; }
    // Container Pin
    void SetContainerPin(const char *container_pin) {
        if (container_pin == nullptr) return;
        container_pin_ = container_pin;
    }
    std::string GetContainerPin() { return container_pin_; }
    // Folder Name
    void SetFolderName(const char *folder_name) {
        if (folder_name == nullptr) return;
        folder_name_ = folder_name;
    }
    std::string GetFolderName() { return folder_name_; }

    // Client ID
    void SetClientId(const char *client_id) {
        if (client_id == nullptr) return;
        client_id_ = client_id;
    }
    std::string GetClientId() { return client_id_; }

    // Client Type
    void SetClientType(const char *client_type) {
        if (client_type == nullptr) return;
        client_type_ = client_type;
    }
    std::string GetClientType() { return client_type_; }

    // Whether init
    bool isInitialized() const { return isInitialized_; }

    // Whether to call hardware
    bool isHardWare() const { return isHardWare_; }

    // Class Method
    bool Initialize();
    bool UnInitialize();

private:
    // Initialized Status
    bool isInitialized_ = false;

    // Handle info
    std::string folder_name_;
    std::string client_id_;
    std::string client_type_;

    // Container Name And Pin
    std::string container_name_;
    std::string container_pin_;

    // HardWare Status
    bool isHardWare_ = false;
};

}

#endif //CYBERLIB_BUILD_HANDLER_H
