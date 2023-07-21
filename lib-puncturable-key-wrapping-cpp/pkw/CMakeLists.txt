# much simpler to work with secure cloud storage

find_package(cryptoPP REQUIRED)

file(GLOB_RECURSE HEADER_FILES
        *.h
        )

file(GLOB_RECURSE SOURCE_FILES
        *.cpp)

add_library(PKWLib STATIC ${HEADER_FILES} ${SOURCE_FILES})

target_link_libraries(PKWLib PRIVATE cryptopp::cryptopp)