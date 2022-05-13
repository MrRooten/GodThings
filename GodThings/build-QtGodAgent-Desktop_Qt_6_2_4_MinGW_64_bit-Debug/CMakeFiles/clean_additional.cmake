# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Debug")
  file(REMOVE_RECURSE
  "CMakeFiles\\QtGodAgent_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\QtGodAgent_autogen.dir\\ParseCache.txt"
  "QtGodAgent_autogen"
  )
endif()
