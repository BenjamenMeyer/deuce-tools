#!/bin/bash

# Script variables
POSITIVE_VALUE="yes"
NEGATIVE_VALUE="no"

SHOW_HELP="${NEGATIVE_VALUE}"
REBUILD_ENV="${NEGATIVE_VALUE}"
CREATE_VAULT="${NEGATIVE_VALUE}"
DELETE_VAULT="${NEGATIVE_VALUE}"
PREPARE_ONLY="${NEGATIVE_VALUE}"
VALIDATE_ONLY="${NEGATIVE_VALUE}"
CLEANUP_ONLY="${NEGATIVE_VALUE}"
GENERATE_DATA="${POSITIVE_VALUE}"
LIST_VAULT="${NEGATIVE_VALUE}"
MISSING_DATA_TEST="${NEGATIVE_VALUE}"
SWIFT_SCRIPT="./tools/swift.py"

AUTH_SERVICE='rackspace'


BLOCK_COUNT=20
CACHE_EXPIRATION=3600
DATA_EXPIRATION=1

# Script argument names
PARAMETER_CLEANUP_ONLY="--cleanup-only"
PARAMETER_CREATE="--create"
PARAMETER_CREATE_SHORT="-c"
PARAMETER_DC="--dc"
PARAMETER_DELETE="--delete"
PARAMETER_DELETE_SHORT="-d"
PARAMETER_DEUCE_SERVER="--deuce-server"
PARAMETER_DEUCE_SERVER_SHORT="-ds"
PARAMETER_HELP="--help"
PARAMETER_HELP_SHORT="-h"
PARAMETER_MISSING_STORAGE_DATA_TEST="--missing-data-test"
PARAMETER_PREPARE_ONLY="--prepare-only"
PARAMETER_REBUILD="--rebuild"
PARAMETER_REBUILD_SHORT="-r"
PARAMETER_SKIP_DATA_GENERATION="--skip-data-generation"
PARAMETER_SWIFT_SCRIPT="--swift-script"
PARAMETER_USER_CONFIG="--user-config"
PARAMETER_VALIDATE_ONLY="--validate-only"
PARAMETER_VAULT_BLOCK_LIST="--block-list-vault-only"
PARAMETER_VAULT_FILE_LIST="--file-list-vault-only"
PARAMETER_VAULT_LIST_VAULT_BLOCKS="blocks"
PARAMETER_VAULT_LIST_VAULT_FILES="files"
PARAMETER_VAULT_NAME="--vault-name"

# Parse the script arguments
for arg in $@
do
	if [ -v ARG_PARAMETER_VALUE ]; then
		case "${ARG_PARAMETER_VALUE}" in
			"${PARAMETER_DC}")
				DC="${arg}"
				;;
			"${PARAMETER_DEUCE_SERVER}")
				DEUCE_SERVER="${arg}"
				;;
			"${PARAMETER_SWIFT_SCRIPT}")
				SWIFT_SCRIPT="${arg}"
				;;
			"${PARAMETER_USER_CONFIG}")
				USER_DATA="${arg}"
				;;
			"${PARAMETER_VAULT_NAME}")
				VAULT_NAME="${arg}"
				;;
			*)
				echo "Missing parameter value for ${ARG_PARAMETER_VALUE}"
				SHOW_HELP="${POSITIVE_VALUE}"
				;;
		esac
		unset ARG_PARAMETER_VALUE
	else
		case "${arg}" in
			"${PARAMETER_CLEANUP_ONLY}")
				VALIDATE_ONLY="${NEGATIVE_VALUE}"
				CLEANUP_ONLY="${POSITIVE_VALUE}"
				;;
			"${PARAMETER_CREATE}")
				CREATE_VAULT="${POSITIVE_VALUE}"
				;;
			"${PARAMETER_CREATE_SHORT}")
				CREATE_VAULT="${POSITIVE_VALUE}"
				;;
			"${PARAMETER_DC}")
				ARG_PARAMETER_VALUE="${arg}"
				;;
			"${PARAMETER_DELETE}")
				DELETE_VAULT="${POSITIVE_VALUE}"
				;;
			"${PARAMETER_DELETE_SHORT}")
				DELETE_VAULT="${POSITIVE_VALUE}"
				;;
			"${PARAMETER_DEUCE_SERVER}")
				ARG_PARAMETER_VALUE="${arg}"
				;;
			"${PARAMETER_DEUCE_SERVER_SHORT}")
				ARG_PARAMETER_VALUE="${PARAMETER_DEUCE_SERVER}"
				;;
			"${PARAMETER_HELP}")
				SHOW_HELP="${POSITIVE_VALUE}"
				;;
			"${PARAMETER_HELP_SHORT}")
				SHOW_HELP="${POSITIVE_VALUE}"
				;;
			"${PARAMETER_MISSING_STORAGE_DATA_TEST}")
				MISSING_DATA_TEST="${POSITIVE_VALUE}"
				;;
			"${PARAMETER_PREPARE_ONLY}")
				PREPARE_ONLY="${POSITIVE_VALUE}"
				GENERATE_DATA="${NEGATIVE_VALUE}"
				;;
			"${PARAMETER_REBUILD}")
				REBUILD_ENV="${POSITIVE_VALUE}"
				;;
			"${PARAMETER_REBUILD_SHORT}")
				REBUILD_ENV="${POSITIVE_VALUE}"
				;;
			"${PARAMETER_SKIP_DATA_GENERATION}")
				GENERATE_DATA="${NEGATIVE_VALUE}"
				;;
			"${PARAMETER_SWIFT_SCRIPT}")
				ARG_PARAMETER_VALUE="${arg}"
				;;
			"${PARAMETER_USER_CONFIG}")
				ARG_PARAMETER_VALUE="${arg}"
				;;
			"${PARAMETER_VALIDATE_ONLY}")
				VALIDATE_ONLY="${POSITIVE_VALUE}"
				CLEANUP_ONLY="${NEGATIVE_VALUE}"
				;;
			"${PARAMETER_VAULT_BLOCK_LIST}")
				LIST_VAULT="${PARAMETER_VAULT_LIST_VAULT_BLOCKS}"
				;;
			"${PARAMETER_VAULT_FILE_LIST}")
				LIST_VAULT="${PARAMETER_VAULT_LIST_VAULT_FILES}"
				;;
			"${PARAMETER_VAULT_NAME}")
				ARG_PARAMETER_VALUE="${arg}"
				;;
			*)
				SHOW_HELP="${POSITIVE_VALUE}"
				;;
		esac
	fi
	
done

if [ "${SHOW_HELP}" == "${NEGATIVE_VALUE}" ]; then
	# Check for required parameters
	if [ ! -v USER_DATA ]; then
		echo "Missing user authentication data"
		SHOW_HELP="${POSITIVE_VALUE}"
	elif [ ! -v DC ]; then
		echo "Missing Data Center to use"
		SHOW_HELP="${POSITIVE_VALUE}"
	elif [ ! -v DEUCE_SERVER ]; then
		echo "Missing Deuce Server Address to use"
		SHOW_HELP="${POSITIVE_VALUE}"
	elif [ ! -v VAULT_NAME ]; then
		echo "Missing Deuce Vault Name to use"
		SHOW_HELP="${POSITIVE_VALUE}"
	fi
fi

if [ "${SHOW_HELP}" == "${POSITIVE_VALUE}" ]; then
	echo -n "${0} ${PARAMETER_USER_CONFIG} <JSON config file> ${PARAMETER_DC} <datacenter> ${PARAMETER_DEUCE_SERVER} <server address> ${PARAMETER_VAULT_NAME} <vault name>"
	echo -n " [${PARAMETER_REBUILD}] [${PARAMETER_REBUILD_SHORT}] [${PARAMETER_CREATE}] [${PARAMETER_CREATE_SHORT}] [${PARAMETER_DELETE}] [${PARAMETER_DELETE_SHORT}]"
	echo -n " [${PARAMETER_CLEANUP_ONLY}] [${PARAMETER_PREPARE_ONLY}] [${PARAMETER_VALIDATE_ONLY}]"
	echo -n " [${PARAMETER_SKIP_DATA_GENERATION}] [${PARAMETER_MISSING_STORAGE_DATA_TEST}] [${PARAMETER_SWIFT_SCRIPT}]"
	echo -n " [${PARAMETER_VAULT_BLOCK_LIST}] [${PARAMETER_VAULT_FILE_LIST}]"
	echo -n " [${PARAMETER_HELP}] [${PARAMETER_HELP_SHORT}]"
	echo
	echo
	echo "  ${PARAMETER_CLEANUP_ONLY}            only perform the cleanup operation"
	echo "  ${PARAMETER_CREATE}                  create the vault"
	echo "  ${PARAMETER_DC}                      datacenter the deuce server is located in"
	echo "  ${PARAMETER_DELETE}                  delete the vault"
	echo "  ${PARAMETER_DEUCE_SERVER}            deuce server to use"
	echo "  ${PARAMETER_HELP}                    show this message"
	echo "  ${PARAMETER_MISSING_STORAGE_DATA_TEST}       Enable testing of missing storage data"
	echo "  ${PARAMETER_PREPARE_ONLY}            only perform the preparation (create/destroy) steps"
	echo "  ${PARAMETER_REBUILD}                 rebuild the virtual environment"
	echo "  ${PARAMETER_SKIP_DATA_GENERATION}    skip adding data to the vault"
	echo "  ${PARAMETER_SWIFT_SCRIPT}            script for modifying the Swift Storage Backend"
	echo "  ${PARAMETER_USER_CONFIG}             user authentication data"
	echo "  ${PARAMETER_VALIDATE_ONLY}           only perform the validation operation"
	echo "  ${PARAMETER_VAULT_BLOCK_LIST}   only list the blocks in the vault"
	echo "  ${PARAMETER_VAULT_FILE_LIST}    only list the files in the vault"
	echo "  ${PARAMETER_VAULT_NAME}              name of the vault to use"
	echo
	echo "  ${PARAMETER_CREATE_SHORT}                        alias for ${PARAMETER_CREATE}"
	echo "  ${PARAMETER_DELETE_SHORT}                        alias for ${PARAMETER_DELETE}"
	echo "  ${PARAMETER_DEUCE_SERVER_SHORT}                       alias for ${PARAMETER_DEUCE_SERVER}"
	echo "  ${PARAMETER_REBUILD_SHORT}                        alias for ${PARAMETER_REBUILD}"
	echo "  ${PARAMETER_HELP_SHORT}                        alias for ${PARAMETER_HELP}"
	exit 0
fi

if [ "${REBUILD_ENV}" == "${POSITIVE_VALUE}" ]; then
	echo "Rebuilding environment..."
	if [ -d env ]; then
		rm -Rf env
	fi

	virtualenv -p `which python3` env
	source env/bin/activate
	pip install python-swiftclient
	pip install . --pre deuce-client

else
	source env/bin/activate

fi

run_valere()
	{
	if [ "${PREPARE_ONLY}" == "${POSITIVE_VALUE}" ]; then
		return 0
	fi

	if [ "${CLEANUP_ONLY}" == "${NEGATIVE_VALUE}" ]; then
		echo "Validating Vault"
		deucevalere --user-config ${USER_DATA} --url ${DEUCE_SERVER} -dc ${DC} --auth-service ${AUTH_SERVICE} --vault-name ${VAULT_NAME} --cache-expiration ${CACHE_EXPIRATION} --data-expiration ${DATA_EXPIRATION} validate
	fi

	if [ "${VALIDATE_ONLY}" == "${NEGATIVE_VALUE}" ]; then
		if [ "${CLEANUP_ONLY}" == "${NEGATIVE_VALUE}" ]; then
			sleep 1
		fi
		echo "Cleaning up Vault"
		deucevalere --user-config ${USER_DATA} --url ${DEUCE_SERVER} -dc ${DC} --auth-service ${AUTH_SERVICE} --vault-name ${VAULT_NAME} --cache-expiration ${CACHE_EXPIRATION} --data-expiration ${DATA_EXPIRATION} cleanup
	fi
	}

create_vault()
	{
	deuceclient --user-config ${USER_DATA} --url ${DEUCE_SERVER} -dc ${DC} --auth-service ${AUTH_SERVICE} vault create --vault-name ${VAULT_NAME}
	}

detect_vault()
	{
	deuceclient --user-config ${USER_DATA} --url ${DEUCE_SERVER} -dc ${DC} --auth-service ${AUTH_SERVICE} vault exists --vault-name ${VAULT_NAME}
	local -i retval=$?
	return ${retval}
	}

delete_vault()
	{
	detect_vault
	if [ $? -eq 0 ]; then
		echo "	Deleting files..."
		delete_files
		echo "	Deleting blocks..."
		delete_blocks
		echo "	Cleaning up Vault..."
		run_valere
		echo "	Deleting the Vault..."
		deuceclient --user-config ${USER_DATA} --url ${DEUCE_SERVER} -dc ${DC} --auth-service ${AUTH_SERVICE} vault delete --vault-name ${VAULT_NAME}
	else
		echo "	Vault does not exist. Unable to cleanup"
	fi
	}

upload_file()
	{
	deuceclient --user-config ${USER_DATA} --url ${DEUCE_SERVER} -dc ${DC} --auth-service ${AUTH_SERVICE} files --vault-name ${VAULT_NAME} upload --content ${1}
	return $?
	}

file_list()
	{
	deuceclient --user-config ${USER_DATA} --url ${DEUCE_SERVER} -dc ${DC} --auth-service ${AUTH_SERVICE} files --vault-name ${VAULT_NAME} list 
	return $?
	}

delete_file()
	{
	local file_id="${1}"
	if [ -n "${file_id}" ]; then
		deuceclient --user-config ${USER_DATA} --url ${DEUCE_SERVER} -dc ${DC} --auth-service ${AUTH_SERVICE} files --vault-name ${VAULT_NAME} delete --file-id ${file_id} 
		return $?
	else
		echo "File ID must be specified"
		return 1
	fi
	}

upload_and_delete_file()
	{
	local FILE_ID=`deuceclient --user-config ${USER_DATA} --url ${DEUCE_SERVER} -dc ${DC} --auth-service ${AUTH_SERVICE} files --vault-name ${VAULT_NAME} upload --content ${1} | grep "File ID" | cut -f 2 -d ':'`

	delete_file ${FILE_ID}
	return $?
	}

delete_files()
	{
	for file_id in `deuceclient --user-config ${USER_DATA} --url ${DEUCE_SERVER} -dc ${DC} --auth-service ${AUTH_SERVICE} files --vault-name ${VAULT_NAME} list | tr -s '\t' ';' | grep '^;' | cut -f 2 -d ';'`
	do
		delete_file ${file_id}
	done
	return 0
	}

upload_block()
	{
	deuceclient --user-config ${USER_DATA} --url ${DEUCE_SERVER} -dc ${DC} --auth-service ${AUTH_SERVICE} blocks --vault-name ${VAULT_NAME} upload --block-content ${1}
	return $?
	}

delete_block()
	{
	deuceclient --user-config ${USER_DATA} --url ${DEUCE_SERVER} -dc ${DC} --auth-service ${AUTH_SERVICE} blocks --vault-name ${VAULT_NAME} delete --block-id ${1}
	return $?
	}

block_list()
	{
	deuceclient --user-config ${USER_DATA} --url ${DEUCE_SERVER} -dc ${DC} --auth-service ${AUTH_SERVICE} blocks --vault-name ${VAULT_NAME} list 
	return $?
	}

delete_blocks()
	{
	for block_id in `deuceclient --user-config ${USER_DATA} --url ${DEUCE_SERVER} -dc ${DC} --auth-service ${AUTH_SERVICE} blocks --vault-name ${VAULT_NAME} list  | tr -s '\t' ';' | grep '^;' | cut -f 2 -d ';'`
	do
		delete_block ${block_id}
	done
	return 0
	}

delete_storage_object()
	{
	local STORAGE_OBJECT="${1}"
	python ${SWIFT_SCRIPT} --user-config ${USER_DATA} -dc ${DC} vault object --vault-name ${VAULT_NAME} delete --storage-block-id "${STORAGE_OBJECT}"
	}

delete_storage_data()
	{
	for SWIFT_OBJECT in `python ${SWIFT_SCRIPT} --user-config ${USER_DATA} -dc ${DC} vault object --vault-name ${VAULT_NAME} list`
	do
		delete_storage_object "${SWIFT_OBJECT}"
	done
	}

delete_storage_matching_data()
	{
	local block_id=${1}
	for SWIFT_OBJECT in `python ${SWIFT_SCRIPT} --user-config ${USER_DATA} -dc ${DC} vault object --vault-name ${VAULT_NAME} list`
	do
		local storage_block_id=`echo ${SWIFT_OBJECT} | cut -f 1 -d '_'`
		if [ "${storage_block_id}" == "${block_id}" ]; then
			echo "		Requesting deletion of storage object ${storage_block_id}..."
			delete_storage_object "${SWIFT_OBJECT}"
		fi
	done
	}

make_expired_data()
	{
	upload_and_delete_file ChangeLog
	return $?
	}

make_orphaned_data()
	{
	local DATA_TO_UPLOAD="AUTHORS LICENSE"
	echo "	Creating files"
	for SOME_DATA in ${DATA_TO_UPLOAD}
	do
		echo "		Uploading ${SOME_DATA} as file"
		upload_file ${SOME_DATA}
	done
	for x in $(eval echo "{1..${BLOCK_COUNT}}")
	do
		echo "	Uploading orphaned copies ${x} of ${BLOCK_COUNT}"
		for SOME_DATA in ${DATA_TO_UPLOAD}
		do
			echo "		Uploading ${SOME_DATA} as block"
			upload_block ${SOME_DATA}
		done
	done
	return 0
	}

make_missing_data()
	{
	local DATA_FILE=tox.ini
	local SHA1=`sha1sum ${DATA_FILE} | cut -f 1 -d ' '`
	upload_file ${DATA_FILE}
	echo "	Deleting storage data matching ${SHA1} for file ${DATA_FILE}..."
	delete_storage_matching_data "${SHA1}"
	}

list_files_and_blocks()
	{
	echo "Files"
	echo "--------------------------------"
	file_list
	echo

	echo "Blocks"
	echo "--------------------------------"
	block_list
	echo
	}

generate_data()
	{
	if [ "${GENERATE_DATA}" == "${POSITIVE_VALUE}" ]; then

		list_files_and_blocks

		echo "Create expired data"
		make_expired_data
		block_list

		if [ "${MISSING_DATA_TEST}" == "${POSITIVE_VALUE}" ]; then
			echo "Creating missing data"
			make_missing_data
		fi

		echo "Create orphaned data"
		make_orphaned_data
		block_list

		list_files_and_blocks
	fi
	}


run_test()
	{
	echo "Testing Empty Vault"
	run_valere

	generate_data

	echo "Cleanup orphaned data"
	run_valere
	}

if [ "${LIST_VAULT}" == "${PARAMETER_VAULT_LIST_VAULT_FILES}" ]; then
	file_list
	exit $?
elif [ "${LIST_VAULT}" == "${PARAMETER_VAULT_LIST_VAULT_BLOCKS}" ]; then
	block_list
	exit $?
fi

if [ "${DELETE_VAULT}" == "${POSITIVE_VALUE}" ]; then
	echo "Cleaning up the existing vault..."
	delete_vault
	let -i delete_return_value=$?
	if [ "${PREPARE_ONLY}" == "${POSITIVE_VALUE}" ]; then
		exit ${delete_return_value}
	fi
fi

if [ "${CREATE_VAULT}" != "${POSITIVE_VALUE}" ]; then
	echo "Attempting to detect Vault - ${VAULT_NAME}..."
	detect_vault
	if [ $? -eq 0 ]; then
		echo "Vault exists."
	else
		echo "Vault does not exist. Marking it to be created"
		CREATE_VAULT="${POSITIVE_VALUE}"
	fi
fi

if [ "${CREATE_VAULT}" == "${POSITIVE_VALUE}" ]; then
	create_vault
	let -i create_return_value=$?
	if [ "${PREPARE_ONLY}" == "${POSITIVE_VALUE}" ]; then
		exit ${create_return_value}
	fi
fi

echo "Running Tests..."
run_test
