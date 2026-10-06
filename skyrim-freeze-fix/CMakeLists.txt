cmake_minimum_required(VERSION 3.26)

project(WorkerSpinLockFix
    VERSION       2.6.4
    DESCRIPTION   "SKSE hard-freeze recovery for Skyrim SE/AE. v2.6.4 adds verified active WaitForJobTask recovery and progress-gated render-side Site-A deep recovery with bounded multi-event continuation and targeted handle-reference diagnostics."
    LANGUAGES     CXX
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

find_package(CommonLibSSE  CONFIG REQUIRED)
find_package(tomlplusplus  CONFIG REQUIRED)
find_package(safetyhook    CONFIG REQUIRED)

set(SOURCES
    src/main.cpp
    src/Config.cpp
    src/Logger.cpp
    src/Hooks.cpp
    src/Stats.cpp
    src/Phase4Defer.cpp
    src/SkyrimAnchors.cpp
    src/JobWaitBreaker_v264.cpp
    src/SiteABreaker.cpp
    src/SiteARenderBreaker_v264.cpp
    src/LeakedSpinLockBreaker.cpp
)

set(HEADERS
    src/PCH.h
    src/Config.h
    src/Logger.h
    src/Hooks.h
    src/Stats.h
    src/Phase4Defer.h
    src/SkyrimAnchors.h
    src/JobWaitBreaker.h
    src/SiteABreaker.h
    src/SiteARenderBreaker.h
    src/LeakedSpinLockBreaker.h
    src/RecoveryPolicy.h
)

add_commonlibsse_plugin(${PROJECT_NAME}
    SOURCES ${SOURCES} ${HEADERS}
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_precompile_headers(${PROJECT_NAME}
    PRIVATE
        src/PCH.h
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        tomlplusplus::tomlplusplus
        safetyhook::safetyhook
)

target_compile_definitions(${PROJECT_NAME}
    PRIVATE
        WSLF_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
        WSLF_VERSION_MINOR=${PROJECT_VERSION_MINOR}
        WSLF_VERSION_PATCH=${PROJECT_VERSION_PATCH}
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
)

if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE
        /W4
        /permissive-
        /Zc:preprocessor
        /Zc:__cplusplus
        /utf-8
        /EHsc
        /MP
        /Zi
        /wd4324
    )
    target_link_options(${PROJECT_NAME} PRIVATE
        /DEBUG:FULL
        "$<$<CONFIG:Release>:/OPT:REF;/OPT:ICF>"
    )
endif()
