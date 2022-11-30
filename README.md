# Godthings
This project is a framework of Windows system analysis and provide some system api to write C or Python code to extend the function of this system. (The code most of it is written in C++/C#, but there are some necessary python libraries so the github code analysis show the python code is most of this project)
## Godthings.sys
  This is kernel driver of this project that supply some kernel mode ability.This must be developped in VS2019,but now I'm in VS2022(Too lazy to install VS2019,So may quit for a while)
  
## GodAgent.exe
  This is the main program of this project.
  ### Args
    GodAgent.exe <subcommand> <option>
      gui_serve: Run the GUI Serve
      info_module: Module Information
      run_module <module>: Run a module
      run_all: Run all autorun-able modules
        --export-csv: export file to csv named by ${Path}.${ModuleName}.csv
      list_modules: List all modules
    
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
        Prefetch    [almost done]
        Amcache     [todo]
        dmp         [todo]
        JumpListFile[todo]
        SRUMFile    [todo]
        evtx        [doing]
    
    Registry parse:
        ShimCache (AppCompatCache)   [todo]
        UserAssist                   [todo]
        MUICache                     [todo]
        RunMRU                       [todo]
        AppCompatFlags Registry Keys [todo]
        Background Activity Moderator[todo]
        RecentApps                   [todo]
    
    Other:
        schdule task [todo]
        
        

    get_stat_info(file_path)
        Return the stat info of file

    open_fileinfo_cache(...)
        Open fileinfo cache to cache fileinfo


