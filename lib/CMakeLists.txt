# libbuxton2.so build
SET(TARGET buxton2)

SET(SRC buxton2.c
	../common/proto.c
	../common/serialize.c
	../common/common.c)
INCLUDE_DIRECTORIES(include)
ADD_LIBRARY(${TARGET} SHARED ${SRC})
SET_TARGET_PROPERTIES(${TARGET} PROPERTIES
		COMPILE_FLAGS "-fvisibility=hidden"
		VERSION ${VERSION}
		SOVERSION ${MAJVER}
)
TARGET_LINK_LIBRARIES(${TARGET} ${PKGS_LDFLAGS})
INSTALL(TARGETS ${TARGET} DESTINATION ${LIB_INSTALL_DIR} COMPONENT RuntimeLibraries)

# buxton2.pc
CONFIGURE_FILE(buxton2.pc.in buxton2.pc @ONLY)
INSTALL(FILES buxton2.pc DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)

# buxton2.h
INSTALL(FILES include/buxton2.h DESTINATION ${INCLUDE_INSTALL_DIR})
