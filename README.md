# Godthings
This project is a framework of Windows system analysis and provide some system api to write C or Python code to extend the function of this system. (The code most of it is written in C++/C#, but there are some necessary python libraries so the github code analysis show the python code is most of this project)
## Godthings.sys
  This is kernel driver of this project that supply some kernel mode ability.This must be developped in VS2019,but now I'm in VS2022(Too lazy to install VS2019,So may quit for a while)
  
## GodAgent.exe
  This is main program of this project.
  ### Args
    gui_serve: 
        Start the GUI server and run the GtGui.exe will display the gui
        
    info_module: 
        Info a runnable module
        
    list_modules: 
        List runnable module
        
    python: 
        Run a Python interpreter
        
    run_module <module_name>:
        Run a module by module name
    
  ### Ability
    Process:
        Information gathering [process controlling may be accomplished one day]
    
    Network:
        Information gathering [network controlling may be accomplished one day]
    
    Windows Log:
        Information gathering.... suppose the control of log may not be implement
    
    Account:
        Information gathering
        
    Thread:
        Information gathering  [thread controlling may be accomplished one day]
        
    Registry:
        Information gathering
        
    Embed python interpreter:
        Use those apis to write plugins so no need to compile c code to accomplish the ability you want
        
    System:
        Information gathering
        
    Some Files parse: 
        Prefetch[almost done],Amcache[todo],memory[todo],JumpListFile[todo],SRUMFile[todo]
  ### Extend API [todo]
    Many of api are not expose to python but implement in GodAgent.If you want to use those, this section may helpful.
## GtGui.exe
  This is the gui application of this GodAgent.exe that write in C#/WPF,run this after run the command.(Actually this is not a good gui,I just write it for fun.If you don't want to use it,I understand that.)
  ###
    GodAgent.exe gui_serve

## Python Internal API
  Using help(module) after import the module to get the usage of function
  ### process_internal
    get_pids()
        Return the PROCESSES received by the process.

    get_process_cpu_state(pid)
        Return the process cpu state

    get_process_handle_state(pid)
        Return the process handle state

    get_process_io_state(pid)
        Return the process io state

    get_process_memory_state(pid)
        Return the process memory state

    get_process_name(pid)
        Return the process name

    get_process_security_state(pid)
        Return the process security state

    get_process_username(pid)
        Return the process username
  ### system_internal
    get_basic_info()
        Return the basic info of system

    get_performance_info()
        Return the performance info

    get_processor_info()
        Return the info of processor
  ### registry_internal
    NAME
    registry_internal
    get_value(path,key)
        Return the registry value

    list_names(path)
        List the path's items

    list_subkeys(path)
        List the registry path's subkeys
  ### file_internal
    NAME
    file_internal

    close_fileinfo_cache(...)
        Close fileinfo cache

    get_basic_info(file_path)
        Return the basic info of file

    get_standard_info(file_path)
        Return the standard info of file

    get_stat_info(file_path)
        Return the stat info of file

    open_fileinfo_cache(...)
        Open fileinfo cache to cache fileinfo

  ### account_internal
    FUNCTIONS
    list_usernames()
        List System Usernames
  ### network_intername
    get_connection_by_pid(pid)
        Get Network connection by pid

    get_connections()
        Get Network connections
  ### thread_internal
    get_tids_by_pid(pid)
        Get threads by pid
  ### service_internal
    get_services()
        List System Services
## gtlib[todo]
  This is a python library wrap the internal functions that build in GodAgent.exe.


