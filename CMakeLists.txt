# Standard routine
cmake_minimum_required(VERSION 3.16)
project(aui_app)

set(AUI_VERSION 4b8503d9)

set(BUILD_SHARED_LIBS OFF)

# Use AUI.Boot
file(
        DOWNLOAD
        https://raw.githubusercontent.com/aui-framework/aui/${AUI_VERSION}/aui.boot.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/aui.boot.cmake)
include(${CMAKE_CURRENT_BINARY_DIR}/aui.boot.cmake)

# import AUI
auib_import(aui https://github.com/aui-framework/aui
            COMPONENTS core views network json curl
            VERSION ${AUI_VERSION})


# Create the executable. This function automatically links all sources from the src/ folder, creates CMake target and
# places the resulting executable to bin/ folder.
aui_executable(obs-websocket-cli)

# Link required libs
aui_link(obs-websocket-cli PRIVATE aui::core aui::network aui::json aui::curl aui::crypt)

