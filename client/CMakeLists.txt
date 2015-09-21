# buxtonctl build
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/lib/include)

SET(TARGET "buxton2ctl")
SET(SRC c_main.c
	c_common.c
	c_proc.c
	c_direct.c
	../common/common.c
	../common/direct.c
	../common/backends.c
	../common/config.c
	../common/serialize.c
)
ADD_EXECUTABLE(${TARGET} ${SRC})
SET_TARGET_PROPERTIES(${TARGET} PROPERTIES
		LINK_FLAGS "-fPIE"
)
TARGET_LINK_LIBRARIES(${TARGET} buxton2 -ldl)
INSTALL(TARGETS ${TARGET} DESTINATION bin)

