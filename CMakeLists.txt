cmake_minimum_required(VERSION 3.10)
project(dde-fm-plugin)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_INSTALL_PREFIX /usr)
include(GNUInstallDirs)

find_package(PkgConfig)
pkg_check_modules(DFM REQUIRED dfm-extension)

add_library(andsec-dde-fm-plugin SHARED plugins.cpp plugins.h)
target_link_libraries(andsec-dde-fm-plugin PUBLIC ${DFM_LIBRARIES})
set_target_properties(andsec-dde-fm-plugin PROPERTIES PREFIX "")

install(TARGETS andsec-dde-fm-plugin LIBRARY DESTINATION "${CMAKE_INSTALL_FULL_LIBDIR}/dde-file-manager/plugins/extensions")