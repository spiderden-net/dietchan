cmake_minimum_required(VERSION 2.8)

include(ExternalProject)

set(BUILD_ROOT "${PROJECT_SOURCE_DIR}/build")


IF ("${CMAKE_SYSTEM}" MATCHES "Linux")
	# On Linux we build our own dietlibc and libowfat

	# Workaround for old CMake
	IF (${CMAKE_MAJOR_VERSION} LESS 3)
	SET(HACK1 DOWNLOAD_COMMAND wget -qO- https://www.fefe.de/dietlibc/dietlibc-0.34.tar.xz | unxz | tar xv -C ${PROJECT_SOURCE_DIR}/src/dietlibc --strip-components=1 )
	ENDIF (${CMAKE_MAJOR_VERSION} LESS 3)
	
	ExternalProject_Add(
		dietlibc
		#CVS_REPOSITORY ":pserver:cvs@cvs.fefe.de:/cvs"
		#CVS_MODULE "dietlibc"
		URL "https://www.fefe.de/dietlibc/dietlibc-0.34.tar.xz"
		${HACK1}
		SOURCE_DIR "${PROJECT_SOURCE_DIR}/src/dietlibc"
		PREFIX "${PROJECT_SOURCE_DIR}/.prefix/dietlibc"
		BUILD_IN_SOURCE 1
		BUILD_ALWAYS 1
		CONFIGURE_COMMAND ""
		UPDATE_COMMAND ""
		TEST_COMMAND ""
		PATCH_COMMAND ""
		BUILD_COMMAND make prefix=${BUILD_ROOT}
		INSTALL_COMMAND make prefix=${BUILD_ROOT} install && 
			echo -e "#!/bin/sh\\nDIETHOME=${BUILD_ROOT} ${BUILD_ROOT}/bin/diet gcc \"$@\"" > ${BUILD_ROOT}/diet-gcc &&
			chmod +x ${BUILD_ROOT}/diet-gcc
	)
	
	SET(CMAKE_C_COMPILER ${BUILD_ROOT}/diet-gcc)
	
	# Workaround for old CMake
	IF (${CMAKE_MAJOR_VERSION} LESS 3)
	SET(HACK2 DOWNLOAD_COMMAND wget -qO- https://www.fefe.de/libowfat/libowfat-0.32.tar.xz | unxz | tar xv -C ${PROJECT_SOURCE_DIR}/src/libowfat --strip-components=1 )
	ENDIF ()
	
	ExternalProject_Add(
		libowfat
		#CVS_REPOSITORY ":pserver:cvs@cvs.fefe.de:/cvs"
		#CVS_MODULE "libowfat"
		URL "https://www.fefe.de/libowfat/libowfat-0.32.tar.xz"
		${HACK2}
		SOURCE_DIR "${PROJECT_SOURCE_DIR}/src/libowfat"
		PREFIX "${PROJECT_SOURCE_DIR}/.prefix/libowfat"
		BUILD_IN_SOURCE 1
		BUILD_ALWAYS 1
		CONFIGURE_COMMAND ""
		UPDATE_COMMAND ""
		TEST_COMMAND ""
		PATCH_COMMAND ""
		BUILD_COMMAND DIETHOME=${BUILD_ROOT} make DIET=${BUILD_ROOT}/bin/diet
		INSTALL_COMMAND make DESTDIR=${BUILD_ROOT} install
	)
ELSE ()
	# On other platforms we fallback on the libraries shipped with the distro.
	MESSAGE("System is not Linux. Using stock libc (most likely not dietlibc) and libowfat instead of building from scratch. "
		"Make sure you have libowfat installed.")
	
	# Annoyingly, the libowfat header locations vary from version to version and vendor to vendor.
	# We try to canonicalize them here by trying common variants and creating a symlink to the appropriate directory.
	# The child project will find this symlink and proceed as if nothing happened.

	find_path(LIBOWFAT_0 NAMES libowfat/cdb.h)
	find_path(LIBOWFAT_1 NAMES lowfat/cdb.h)
	find_path(LIBOWFAT_2 NAMES cdb.h)

	IF (LIBOWFAT_0)
		SET(REAL_LIBOWFAT_HEADERS ${libowfat0}/libowfat)
	ELSEIF (LIBOWFAT_1)
		SET(REAL_LIBOWFAT_HEADERS ${libowfat1}/lowfat)
	ELSEIF (LIBOWFAT_2)
		SET(REAL_LIBOWFAT_HEADERS ${libowfat2})
	ELSE ()
		message(FATAL_ERROR "libowfat headers not found")
	ENDIF ()
       
	add_custom_target(libowfat COMMAND ${CMAKE_COMMAND} -E create_symlink ${REAL_LIBOWFAT_HEADERS} ${PROJECT_SOURCE_DIR}/src/libowfat)
ENDIF ()


ExternalProject_Add(
	captcha
	GIT_REPOSITORY "https://gitgud.io/zuse/captcha.git"
	GIT_TAG master
	SOURCE_DIR "${PROJECT_SOURCE_DIR}/src/captcha"
	PREFIX "${PROJECT_SOURCE_DIR}/.prefix/captcha"
	BUILD_IN_SOURCE 1
	BUILD_ALWAYS 1
	UPDATE_COMMAND ""
	INSTALL_COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/src/captcha/captcha ${PROJECT_SOURCE_DIR}
	CMAKE_ARGS -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
	           -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
)

ExternalProject_Add(
	dietchan
	SOURCE_DIR "${PROJECT_SOURCE_DIR}/src/dietchan"
	PREFIX "${PROJECT_SOURCE_DIR}/.prefix/dietchan"
	BUILD_IN_SOURCE 1
	BUILD_ALWAYS 1
	UPDATE_COMMAND ""
	INSTALL_COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/src/dietchan/dietchan ${PROJECT_SOURCE_DIR} &&
	                ${CMAKE_COMMAND} -E copy_directory ${PROJECT_SOURCE_DIR}/src/dietchan/data ${PROJECT_SOURCE_DIR}/data
	CMAKE_ARGS -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
	           -DCMAKE_LIBRARY_PATH=${PROJECT_SOURCE_DIR}/src/libowfat
	           -DCMAKE_INCLUDE_PATH=${PROJECT_SOURCE_DIR}/src
	           -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
)

IF ("${CMAKE_SYSTEM}" MATCHES "Linux")
add_dependencies(libowfat dietlibc)
add_dependencies(captcha  dietlibc)
add_dependencies(dietchan dietlibc)
ENDIF ()

add_dependencies(dietchan libowfat)

# Only for IDE support
FILE(GLOB_RECURSE DIETCHAN_SOURCES "src/dietchan/src/*.c")
add_custom_target(dietchan_src SOURCES ${DIETCHAN_SOURCES})
