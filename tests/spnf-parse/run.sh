#!/bin/bash

apps=`ls ~/workspace/dark-insight-apps/splash-2x/parsec-3.0/ext/splash2x/apps/`

for app in $apps 
do 
  
  echo "app name: ${app}"  
  ./tc ~/workspace/dark-insight-apps/splash-2x/parsec-3.0/ext/splash2x/apps/${app}/inst/amd64-linux.gcc/bin/${app}

  if [ $? -ne 0 ];
  then
	  echo "parsing error occurred at $app"
	  exit
  fi
done

kernel=`ls ~/workspace/dark-insight-apps/splash-2x/parsec-3.0/ext/splash2x/kernels/`
for kernel in $kernels
do 
  
  echo "kernel name: ${kernel}"  
  ./tc ~/workspace/dark-insight-apps/splash-2x/parsec-3.0/ext/splash2x/kernels/${kernel}/inst/amd64-linux.gcc/bin/${kernel}

  if [ $? -ne 0 ];
  then
	  echo "parsing error occurred at $kernel"
	  exit
  fi
done
