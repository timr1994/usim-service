cmake_minimum_required(VERSION 3.10)

#Check for tss2-esys lib
unset(ESYS CACHE)
find_library(ESYS tss2-esys)
if(NOT ESYS)
    message(SEND_ERROR "TSS2-ESYS NOT FOUND")
else()
    message(STATUS "TSS2-ESYS FOUND ${ESYS}")
endif()

#Check for qcbor lib
unset(QCBOR CACHE)
find_library(QCBOR qcbor)
if(NOT QCBOR)
    message(SEND_ERROR "QCBOR NOT FOUND")
else()
    message(STATUS "QCBOR FOUND ${QCBOR}")
endif()

#Check for mbedcrypto lib
unset(MBEDCRYPTO CACHE)
find_library(MBEDCRYPTO mbedcrypto)
if(NOT MBEDCRYPTO)
    message(SEND_ERROR "MBEDCRYPTO NOT FOUND")
else()
    message(STATUS "MBEDCRYPTO FOUND ${MBEDCRYPTO}")
endif()

#Check for yaml lib
unset(YAML CACHE)
find_library(YAML yaml)
if(NOT YAML)
    message(SEND_ERROR "YAML NOT FOUND")
else()
    message(STATUS "YAML FOUND ${YAML}")
endif()

#Check for pthread lib
unset(PTHREAD CACHE)
find_library(PTHREAD pthread)
if(NOT PTHREAD)
    message(SEND_ERROR "PTHREAD NOT FOUND")
else()
    message(STATUS "PTHREAD FOUND ${PTHREAD}")
endif()

#Check for pthread lib
unset(UIIMLIB CACHE)
find_library(UIIMLIB uiim)
if(NOT UIIMLIB)
    message(SEND_ERROR "UIIMLIB NOT FOUND")
else()
    message(STATUS "UIIMLIB FOUND ${UIIMLIB}")
endif()

configure_file(uiim_service_typedefs.h.in ${CMAKE_CURRENT_SOURCE_DIR}/uiim_service_typedefs.h)

if(WHEELFEEDER)
add_executable(uiimd help_functions wheel_feeder hash_message_record session_helper wf_session util/tpm2_util record_list uiimconf service hash_message_list_for_session mtsl/mtsl distributor)
target_link_libraries(uiimd uiim qcbor mbedcrypto yaml tss2-esys pthread)
set_property(TARGET uiimd PROPERTY C_STANDARD 99)
install(TARGETS uiimd DESTINATION bin)

add_executable(uism_viewer log_viewer help_functions wheel_feeder hash_message_record util/tpm2_util record_list uiimconf mtsl/mtsl distributor)
target_link_libraries(uism_viewer uiim qcbor mbedcrypto yaml tss2-esys pthread)
set_property(TARGET uism_viewer PROPERTY C_STANDARD 99)
install(TARGETS uism_viewer DESTINATION bin)
else()
add_executable(uiimd help_functions hash_message_logger hash_message_record session_helper session util/tpm2_util sts_queue/sts_queue record_list uiimconf service hash_message_list_for_session mtsl/mtsl)
target_link_libraries(uiimd uiim qcbor mbedcrypto yaml tss2-esys pthread)
set_property(TARGET uiimd PROPERTY C_STANDARD 99)
install(TARGETS uiimd DESTINATION bin)

add_executable(uism_viewer log_viewer help_functions hash_message_logger hash_message_record util/tpm2_util sts_queue/sts_queue record_list uiimconf mtsl/mtsl)
target_link_libraries(uism_viewer uiim qcbor mbedcrypto yaml tss2-esys pthread)
set_property(TARGET uism_viewer PROPERTY C_STANDARD 99)
install(TARGETS uism_viewer DESTINATION bin)
endif()




