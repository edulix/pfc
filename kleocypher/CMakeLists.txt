project(kleocypher)

find_package(KDE4 REQUIRED)
find_package(Gpgmepp REQUIRED)
find_package(Kleo REQUIRED)
if(NOT KLEO_INCLUDES)
    message(FATAL_ERROR "KLEO_INCLUDES not defined")
else(NOT KLEO_INCLUDES)
    set(HAVE_KLEO_SUPPORT 1)
endif(NOT KLEO_INCLUDES)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h )
include (KDE4Defaults)
cmake_minimum_required(VERSION 2.6.2)

include_directories(
  ${KDE4_INCLUDES}
  ${QT_INCLUDES}
  ${KLEO_INCLUDES}
  ${QGPGME_INCLUDES}
)

set(kleocypher_SRCS
   main.cpp
)
 
kde4_add_ui_files(kleocypher_SRCS mainwindowclass.ui)

kde4_add_executable(kleocypher ${kleocypher_SRCS})


target_link_libraries(kleocypher ${KDE4_KDEUI_LIBS} ${KLEO_LIBRARIES} ${QGPGME_LIBRARIES})

install(TARGETS kleocypher ${INSTALL_TARGETS_DEFAULT_ARGS} )

