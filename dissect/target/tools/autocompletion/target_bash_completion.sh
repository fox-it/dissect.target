#!/bin/env bash

#######################################
# Enables to create a comma seperated list argument
# Arguments:
#   cur: The current argument that the tab completion is busy with
#   list: The list of completion options
# Outputs:
#   list of comma seperated tab completions
#######################################
__comma_seperated_list_completion ()
{
    local cur=${1} list=${2}
    local filtered_list realcur prefix

    if [[ "${cur}" = *,* ]]; then
        realcur=${cur##*,}
        prefix=${cur%,*}

        # Create filtered_list depending on the prefix
        filtered_list=$(__filter_list "${list[@]}" "${prefix}")
        echo $( compgen -W "${filtered_list}" -P "${prefix}," -- ${realcur})
    else
        echo $( compgen -W "${list}" -- ${cur} )
    fi
}

#######################################
# Filters a list based on a comma seperated ${prefix}
#   If a list element is inside ${prefix} it is excluded from the output
# Arguments:
#   prefix: Comma seperated list
#   list: The list of completion options
# Outputs:
#   list of filtered completion outputs
#######################################
__filter_list() {
    # Filter the total array that was already selected.
    local list=(${1}) prefix=${2} filtered_array=()

    for i in ${list[@]}; do
        # Exclude list elements that are in ${prefix}
        if [[ ! (*",${prefix},"* =~ ",${i},") ]]; then
            filtered_array+=(${i})
        fi
    done
    echo "${filtered_array[@]}"
}

#######################################
# A default help command for the target-* commands
# It filters the target-* --help command to get a list of command line arguments
# Globals
#   COMPREPLY: Fills it with help command line arguments
# Outputs:
#   None
#######################################
__target_help() {
    local cur options

    cur=${COMP_WORDS[COMP_CWORD]}
    case "${cur}" in
    -*)
        tool=${COMP_WORDS[0]#*-}
        options=${DISSECT_HELP["$tool"]}
        COMPREPLY=($( compgen -W "${options}" -- ${cur} ))
        ;;
    esac
}

#######################################
# Autocomplete target-* entries with a --function
# sets COMPREPLY for completion argument
# Globals:
#   COMPREPLY
#   DISSECT_PLUGINS: A list of target-query plugins
# Arguments:
#   None
#######################################
__target_function ()
{
    local cur prev
    cur=${COMP_WORDS[COMP_CWORD]}
    prev=${COMP_WORDS[COMP_CWORD-1]}

    case "${prev}" in
    -f | --function )
        COMPREPLY=($(__comma_seperated_list_completion "${cur}" "${DISSECT_PLUGINS}"))
        ;;
    *)
        # Set compreply to command line arguments if -* is detected
        __target_help
        ;;
    esac
}

if command -v target-query &> /dev/null
then
    echo Loading Dissect plugin list
    DISSECT_PLUGINS=$(target-query --quiet --list | grep -e '^\s\+[a-z][a-z\._]\+ -' | awk '{print $1}')

    echo Loading Dissect help prompts
    declare -A DISSECT_HELP
    for x in query dump dd fs mount reg shell
    do
        DISSECT_HELP["$x"]=$(target-$x --quiet --help | grep -Eo ' --?([a-zA-Z]|-)+' | awk '{print $1}' | sort -u)
    done

    complete -F __target_function -o filenames -o default target-query
    complete -F __target_function -o filenames -o default target-dump

    complete -F __target_help -o filenames -o default target-dd
    complete -F __target_help -o filenames -o default target-fs
    complete -F __target_help -o filenames -o default target-mount
    complete -F __target_help -o filenames -o default target-reg
    complete -F __target_help -o filenames -o default target-shell
fi
