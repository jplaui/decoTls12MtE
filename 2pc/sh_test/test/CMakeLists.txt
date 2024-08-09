#Testing macro
macro (add_test_executable_with_lib _name libs)
	add_executable(${_name} "${_name}.cpp")
	target_link_libraries(${_name} ${EMP-OT_LIBRARIES})
endmacro()

macro (add_test_case _name)
	add_test_executable_with_lib(${_name} "")
  	add_test(NAME ${_name} COMMAND "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${_name}" WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/")
endmacro()

macro (add_test_case_with_run _name)
	add_test_executable_with_lib(${_name} "")
	add_test(NAME ${_name} COMMAND "./run" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${_name}" WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/")

endmacro()

# Test cases
add_test_case_with_run(mult3)
add_test_case_with_run(innerprod)
add_test_case_with_run(xtabs)
add_test_case_with_run(prf)
#add_test_case_with_run(prf_2)
add_test_case_with_run(hmac_setup)
#add_test_case_with_run(hmac_setup_2)
add_test_case_with_run(prf_client_finished)
#add_test_case_with_run(prf_client_finished_2)
add_test_case_with_run(hmac_outer_hash)
#add_test_case_with_run(hmac_outer_hash_2)
add_test_case_with_run(prf_server_finished)
