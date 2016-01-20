# buxton2d build

PKG_CHECK_MODULES(D_PKGS REQUIRED libsystemd cynara-client-async gio-2.0 glib-2.0)

FOREACH(flag ${D_PKGS_CFLAGS})
	SET(DAEMON_CFLAGS "${DAEMON_CFLAGS} ${flag}")
ENDFOREACH()

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/lib/include)

SET(TARGET "buxton2d")
SET(SRC main.c
	daemon.c
	socks.c
	cynara.c
	dbus.c
	../common/common.c
	../common/config.c
	../common/backends.c
	../common/serialize.c
	../common/direct.c
	../common/proto.c
)
ADD_EXECUTABLE(${TARGET} ${SRC})
SET_TARGET_PROPERTIES(${TARGET} PROPERTIES
		LINK_FLAGS "-fPIE"
		COMPILE_FLAGS "${DAEMON_CFLAGS}"
)
TARGET_LINK_LIBRARIES(${TARGET} ${PKGS_LDFLAGS} ${D_PKGS_LDFLAGS} -ldl)
INSTALL(TARGETS ${TARGET} DESTINATION sbin)

