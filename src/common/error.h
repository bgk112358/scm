// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//
#ifndef SVKD_BUILD_ERROR_H
#define SVKD_BUILD_ERROR_H

#include <cstdarg>
#include <string>
#include <vector>

namespace cyber {

class Error {

private:
    int code_  = 0;
    std::string message_;

public:
    /**
     * @brief Constructor
     * @param code_    error code
     * @param message_ error message
     */
    Error(int code, std::string & message) {
        code_ = code;
        message_ = message;
    }

    /**
     * @brief  Get the error code from the error object
     * @return error code
     */
    int getCode() const { return code_; }

    /**
     * @brief Get the error message from the error object
     * @return error message
     */
    std::string getMessage() const { return message_; }
};

class Errors
{
private:
    std::vector<Error> errors_;

public:

    /**
     * @brief Default constructor creates a errors object that does not point to
     * any target/destination.
     **/
    Errors() = default;

    /**
     * @brief Copy constructor, creates a copy of a errors object.
     **/
    Errors(const Errors& other) = default;

    /**
     * @brief Move constructor, can be used with `std::move` but does the same as
     * the copy constructor.
     **/
    Errors(Errors&& other) = default;

    /**
     * @brief Move assignment operator, does the same as the copy assignment
     * operator.
     **/
    Errors& operator=(Errors&& other) = default;

    /**
     * @brief Destructor.
     **/
    ~Errors() = default;

    /**
     * @brief Add errors to the error stack
     * @param error  error object
     */
    void pushError(const Error& error) {
        if (errors_.size() > 3) {
            errors_.erase(errors_.begin());
        }
        errors_.push_back(error);
    }

    /**
     * @brief Add errors to the error stack
     * @param code     error code
     * @param message  error message
     */
    void pushError(int code, std::string& message) {
        Error error = Error(code, message);
        printf("message value: %s\n", message.data());
        pushError(error);
    }

    /**
     * @brief Get last error from error stack
     * @return last error object
     */
    Error getLastError() const {
        return errors_.back();
    }

    /**
     * @brief Get error stack
     * @return error stack
     */
    std::vector<Error> getErrors() const {
        return errors_;
    }

    /**
     * @brief Clear error stack
     */
    void clearErrors() {
        errors_.clear();
    }

};

/**
 * @brief Internal global logger.
 **/
extern Errors errors;

}

#endif //SVKD_BUILD_ERROR_H
