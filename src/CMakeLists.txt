cmake_minimum_required(VERSION 3.5)
PROJECT(wssl-wrapper)

message("Wolf SSL Dir ${WOLFSSL_DIR}")
include_directories(${WOLFSSL_DIR}/include)
FILE (GLOB SRCS *.c )

add_library(${PROJECT_NAME} SHARED ${SRCS} )
target_link_libraries(${PROJECT_NAME} -L${WOLFSSL_DIR}/lib)
target_link_libraries(${PROJECT_NAME} -lwolfssl)

if(DEFINED LINKSERVER_STATICALLY)
    add_library(${PROJECT_NAME}-static  STATIC ${SRCS} )
    target_link_libraries(${PROJECT_NAME}-static -L${WOLFSSL_DIR}/lib)
    target_link_libraries(${PROJECT_NAME}-static -lwolfssl)
endif()


set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR}  CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
