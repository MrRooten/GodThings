# Godthings
This project is a framework of Windows system analysis
## Godthings.sys
  This is kernel driver of this project that supply some kernel mode ability.
  
## GodAgent.exe
  This is main program of this project.
  ### Args
    gui_serve: Start the GUI server and run the GtGui.exe will display the gui
    info_module: 
    list_modules:
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
 
## Python internal api
## gtlib[todo]
  This is a python library wrap the functions that implement in GodAgent.exe,

