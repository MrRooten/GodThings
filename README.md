# Godthings
This project is a framework of Windows system analysis and provide some system api to write C or Python code to extend the function of this system. 
## Godthings.sys
  This is kernel driver of this project that supply some kernel mode ability.
  
## GodAgent.exe
  This is main program of this project.
  ### Args
    gui_serve: Start the GUI server and run the GtGui.exe will display the gui
    info_module: 
    list_modules:
    interpreter: Run a Python interpreter
  ### Ability
   #### Process information gathering [process controlling may be accomplished one day]
   #### Network information gathering [network controlling may be accomplished one day]
   #### Log information gathering.... suppose the control of log may not be implement
   #### Account information gathering
   #### Thread information gathering  [thread controlling may be accomplished one day]
   #### Registry information gathering
   #### Embed python interpreter to use those apis to write plugins so no need to compile c code to accomplish the ability you want
   #### System information gathering
  
## GtGui.exe
  This is the gui application of this GodAgent.exe that write in C#/WPF,
 
## Python Internal API
  ### process_internal
  ### system_internal
  ### registry_internal
  ### file_internal
  ### account_internal
  ### network_internal
  ### thread_internal
  ### service_internal
## gtlib[todo]
  This is a python library wrap the functions that implement in GodAgent.exe,

