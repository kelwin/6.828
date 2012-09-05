echo Setting up the environment for debugging gdb.\n

set complaints 1

b internal_error

b info_command
commands
	silent
	return
end

dir .././gdb/../libiberty
dir .././gdb/../bfd
dir .././gdb
dir .
set prompt (top-gdb) 
