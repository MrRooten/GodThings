# Godthings
This project is a framework of Windows system analysis and provide some system api to write C or Python code to extend the function of this system. 
## Godthings.sys
  This is kernel driver of this project that supply some kernel mode ability.This must be developped in VS2019,but now I'm in VS2022(Too lazy to install VS2019,So may quit for a while)
  
## GodAgent.lib
  This is the main program of this project.
  ### Args
    GTExample2.exe <subcommand> <option>
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
        Prefetch    [done]
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
        Background Activity Moderator[done]
        RecentApps                   [todo]
    
    Other:
        schdule task [todo]
        
        

    get_stat_info(file_path)
        Return the stat info of file

    open_fileinfo_cache(...)
        Open fileinfo cache to cache fileinfo

## GTExample2.exe
  ![image](https://user-images.githubusercontent.com/25635931/227888007-9d35f94d-01a1-416e-bd4e-9c8441e7d424.png)
  ### System.LoadedFiles
  ![image](https://user-images.githubusercontent.com/25635931/227888102-870491f3-9075-4fc8-8f06-4da307d95d1a.png)
  ### File.File  
  "file=${path}", the path can be file or directory, if is a directory then show all file types that own by this directory  
  ![image](https://user-images.githubusercontent.com/25635931/227888288-0a9a3f46-3947-4106-9619-1cb335a6e89e.png)
  if there is ending with backslash, then need a double-backslash to escape
  ![image](https://user-images.githubusercontent.com/25635931/227888396-30312726-a87f-46fe-b123-f5ae242e0b8e.png)

