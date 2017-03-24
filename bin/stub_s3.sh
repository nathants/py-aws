aws() {
    if [ "$1" = s3 ]; then
        shift
        python3 -c "from aws.s3_stubbed import main; main()" $@
    else
        echo the only stubbed service is: $ aws s3 ...
        return 1
    fi
}

clear-s3-stubbed() {
    s3-stubbed clear-storage
    unset s3_stubbed_session
    unset -f aws
    unset -f clear-s3-stubbed
}

export -f aws
export -f clear-s3-stubbed
export s3_stubbed_session=$(cat /proc/sys/kernel/random/uuid)
