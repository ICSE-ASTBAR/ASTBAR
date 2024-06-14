# coding=utf-8
import os
import json
import re
import redis
from tqdm import tqdm
import multiprocessing as mp
import hashlib
import pickle

def get_all_files(path):
    file_path = []
    for root, dirs, files in os.walk(path):
        for file in files:
            filepath = os.path.join(root, file)
            file_path.append(filepath)
    return file_path

def connect_redis():
    redis_host = 'redis-url'
    redis_port = 8888
    redis_password = 'password'

    redis_client = redis.Redis(host=redis_host, port=redis_port, password=redis_password)

    if redis_client.ping():
        print('connect success')
    else:
        print('connect fail')
    return redis_client


def extract_ast(file):
    with open(file, 'r') as file:
        decode_Ast = json.load(file)
    # optast = json.loads(file)
    return decode_Ast


def foreach_ast_extract_name(input_json, node_list):
    if isinstance(input_json, dict):
        for k, v in input_json.items():
            if isinstance(v, dict):
                foreach_ast_extract_name(v, node_list)
            elif isinstance(v, list):
                for vv in v:
                    foreach_ast_extract_name(vv, node_list)
            else:
                if k == 'name' and v != 'NULL':
                    node_list.append(v)

    elif isinstance(input_json, list):
        for i in input_json:
            foreach_ast_extract_name(i, node_list)

    return node_list


def slide_word(func: list, l: int = 3) -> list:
    result = []
    if len(func) <= l:
        result.append(tuple(func))
        return result
    for i in range(len(func)):
        word = func[i:i + l]
        if len(word) < l:
            break
        result.append(tuple(word))
    return result


def xxx(input_json, node_list):
    if 'STMT_LIST' in input_json['name'] \
            or 'IF' in input_json['name'] \
            or 'CLASS' in input_json['name'] \
            or 'FUNC_DECL' in input_json['name'] \
            or 'WHILE' in input_json['name'] \
            or 'SWITCH' in input_json['name'] \
            or 'METHOD:' in input_json['name'] \
            or 'TRY' in input_json['name'] \
            or 'CATCH_LIST' in input_json['name'] \
            or 'ARRAY:' in input_json['name'] \
            or 'CONDITIONAL' in input_json['name'] \
            or 'NAMESPACE' in input_json['name'] \
            or 'PROP_GROUP' in input_json['name'] \
            or 'PROP_DECL' in input_json['name'] \
            or 'PROP_ELEM' in input_json['name']:
        for sub in input_json['children']:
            xxx(sub, node_list)
    elif 'FOR' in input_json['name']:
        node_list.append(input_json)
        for sub in input_json['children'][-1:]:
            xxx(sub, node_list)
    elif 'CATCH' in input_json['name']:
        node_list.append(input_json)
        for sub in input_json['children'][-1:]:
            xxx(sub, node_list)
    elif 'RETURN' in input_json['name'] and len(input_json['children']) >= 1:
        if 'ARRAY' in input_json['children'][0]['name']:
            xxx(input_json['children'][0], node_list)
        else:
            node_list.append(input_json)
    elif 'ARRAY_ELEM' in input_json['name'] and len(input_json['children']) >= 1:
        if 'ARRAY' in input_json['children'][0]['name']:
            xxx(input_json['children'][0], node_list)
        else:
            node_list.append(input_json)
    else:
        node_list.append(input_json)

    return node_list


def deal_unique(token):
    keys = []
    top = 0
    for tok in token:
        if len(keys) == 0:
            keys.append(tok)
        elif keys[top] != tok:
            keys.append(tok)
            top += 1
    return keys


def del_foreach_stmt(node_list):
    if len(node_list) == 0:
        return node_list
    if 'FOR' in node_list[0] or 'CATCH' in node_list[0]:
        try:
            index = node_list.index('STMT_LIST')
            return node_list[:index]
        except:
            return node_list
    return node_list


def pruning(node_list):
    if len(node_list) == 0:
        return node_list
    stop_words = {"USE", "PARAM_LIST"}
    if node_list[0] in stop_words:
        return []
    stop_sentences = {('ZVAL', 'void'), ('ZVAL', 'shorttext')}
    if tuple(node_list) in stop_sentences:
        return []
    return node_list



def sub_xxx(sub, node_list):
    if 'ASSIGN(=)' in sub['name']:
        node_list.append('ASSIGN_EQUAL')
        for ssub in sub['children']:
            sub_xxx(ssub, node_list)
    elif 'ARRAY:' in sub['name']:
        for ssub in sub['children']:
            sub_xxx(ssub, node_list)
    elif 'METHOD_CALL' in sub['name']:
        node_list.append('METHOD_CALL')
        for ssub in sub['children']:
            sub_xxx(ssub, node_list)
    elif 'STATIC_CALL' in sub['name']:
        node_list.append('STATIC_CALL')
        for ssub in sub['children']:
            sub_xxx(ssub, node_list)
    elif 'ARG_LIST' in sub['name']:
        node_list.append('ARG_LIST')
        for ssub in sub['children']:
            sub_xxx(ssub, node_list)
    elif 'BINARY_OP(.)' in sub['name']:
        node_list.append('BINARY_OP_DOT')
        for ssub in sub['children']:
            sub_xxx(ssub, node_list)
    elif 'ARRAY_ELEM' in sub['name']:
        for ssub in sub['children']:
            sub_xxx(ssub, node_list)
    elif 'CALL' in sub['name']:
        node_list.append('CALL')
        for ssub in sub['children']:
            sub_xxx(ssub, node_list)
    elif 'PROP' in sub['name']:
        node_list.append('PROP')
        for ssub in sub['children']:
            sub_xxx(ssub, node_list)
    elif 'STMT_LIST' in sub['name']:
        node_list.append('STMT_LIST')
        for ssub in sub['children']:
            sub_xxx(ssub, node_list)
    elif 'RETURN' in sub['name']:
        node_list.append('RETURN')
        for ssub in sub['children']:
            sub_xxx(ssub, node_list)
    elif 'CLOSURE' in sub['name']:
        node_list.append('CLOSURE')
        for ssub in sub['children']:
            sub_xxx(ssub, node_list)
    elif 'PARAM_LIST' in sub['name']:
        node_list.append('PARAM_LIST')
        for ssub in sub['children']:
            sub_xxx(ssub, node_list)
    elif 'CLOSURE_USES' in sub['name']:
        node_list.append('CLOSURE_USES')
        for ssub in sub['children']:
            sub_xxx(ssub, node_list)
    elif 'PARAM' in sub['name']:
        node_list.append('PARAM')
        for ssub in sub['children']:
            sub_xxx(ssub, node_list)
    else:
        node_list.append(sub)

    return node_list



def md5_hash(data):
    byte_data = str(data).encode('utf-8')
    md5 = hashlib.md5()
    md5.update(byte_data)
    return md5.hexdigest()


def extract_3gram_subtree(input_json, flag):
    ast_list = xxx(input_json, [])
    gram_tree = []
    echo_kind = ['ZVAL', 'ECHO', 'longtext', 'shorttext', 'long_danger_info']
    exit_kind = ['ZVAL', 'EXIT', 'longtext', 'shorttext', 'long_danger_info']
    for sub in ast_list:
        node_list = foreach_ast_extract_name(sub, [])
        node_list = deal_node_list(node_list, flag)

        if 'ARRAY' in node_list or 'PROP' in node_list or 'ARG_LIST' in node_list:
            ast_list = sub_xxx(sub, [])
            node_list = []
            for ssub in ast_list:
                if isinstance(ssub, str):
                    node_list.append([ssub])
                else:
                    t = foreach_ast_extract_name(ssub, [])
                    t = deal_node_list(t, flag)
                    if len(t) > 0:
                        if len(node_list) == 0:
                            node_list.append(t)
                        elif t != node_list[-1]:
                            try:
                                if t != node_list[-4] and t != node_list[-3] and t != node_list[-2]:
                                    node_list.append(t)
                            except:
                                try:
                                    if t != node_list[-3] and t != node_list[-2]:
                                        node_list.append(t)
                                except:
                                    try:
                                        if t != node_list[-2]:
                                            node_list.append(t)
                                    except:
                                        node_list.append(t)

            node_list = deal_unique(node_list)
            node_list = [k for i in node_list for k in i]

        node_list = del_foreach_stmt(node_list)
        node_list = deal_unique(node_list)
        node_list = pruning(node_list)
        if len(node_list) > 0:
            if len(gram_tree) > 0:
                if define_similarity_opc(set(echo_kind), node_list) == 1.0:
                    node_list = ['ECHO', 'ZVAL', 'info']
                    if gram_tree[-1] == tuple(node_list):
                        continue
                    else:
                        gram_tree.append(tuple(node_list))
                elif define_similarity_opc(set(exit_kind), node_list) == 1.0:
                    node_list = ['EXIT', 'ZVAL', 'info']
                    if gram_tree[-1] == tuple(node_list):
                        continue
                    else:
                        gram_tree.append(tuple(node_list))
                elif gram_tree[-1] == tuple(node_list):
                    continue
                else:
                    gram_tree.append(tuple(node_list))
            else:
                if define_similarity_opc(set(echo_kind), node_list) == 1.0:
                    node_list = ['ECHO', 'ZVAL', 'info']
                    gram_tree.append(tuple(node_list))
                elif define_similarity_opc(set(exit_kind), node_list) == 1.0:
                    node_list = ['EXIT', 'ZVAL', 'info']
                    gram_tree.append(tuple(node_list))
                else:
                    gram_tree.append(tuple(node_list))
    return gram_tree



def define_similarity_opc(a, b):
    return len(a.intersection(set(b))) / len(set(b))


def type_file_param_standard(param):
    spot = ['_POST', '_GET', '_REQUEST', '_COOKIE', '_SERVER', '_FILES', '_ENV', '_HEADERS', '_SESSION']
    if param in spot:
        return "spot"
    if param.lower() == 'php\/\/input':
        return "spot"

    if (param.startswith('http') and 'href=' not in param) or (param.startswith('https') and 'href=' not in param):
        if param.lower().endswith('.jpg') or param.lower().endswith('.ico') or param.lower().endswith(
                '.jpeg') or param.lower().endswith('.png'):
            return "pic_file"
        if len(param.split('.')) == 2:
            return param.split('.')[-1] + '_file'
        return "url"

    if re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", param):
        if param.lower().startswith('\\/www\\/wwwroot') or param.lower().startswith('c') or param.lower().startswith('d'):
            type = param.split('.')[-1]
            if len(type) > 0 and len(param.split('.')) > 1 and type.isalpha():
                return type + "_file"
            else:
                return "default_file"
        if param.lower().endswith('.jpg') or param.lower().endswith('.ico') or param.lower().endswith(
                '.jpeg') or param.lower().endswith('.png'):
            return "pic_file"
        return "url"

    type = param.split('.')[-1]
    if len(type) > 0 and len(param.split('.')) > 1 and type.isalpha():
        return type + "_file"
    if param.isdigit():
        return "number"
    if param.startswith("JPEG"):
        return "JFIF"

    if param.isalpha() and len(param) > 2:
        return param
    if param.isalpha():
        return "variable"
    match = re.match(r'[a-zA-Z]+[0-9]+', param)
    if match:
        if match.group() == param:
            return "variable"
    upper = param.replace('_', '')
    match = re.match(r'[A-Za-z]+', upper)
    if match:
        if match.group() == upper:
            return param

    func_name = ['join', 'feof', 'pclose', 'chr', 'ord', 'htmlentities', 'void', 'defined', 'define', 'ftp_exec',
                 'apache_setenv', 'file_put_contents', 'parsekit_compile_file', 'session_set_save_handler',
                 'sqlite_open',
                 'ldap_search', 'fwrite', 'posix_mknod', 'eio_chmod', 'usleep', 'eio_fchown', 'dbx_query',
                 'runkit_method_copy', 'ftp_delete', 'imap_mail', 'imagecreatefromjpg', 'eio_unlink',
                 'strrev', 'runkit_function_redefine', 'ldap_read', 'imap_open', 'print', 'eio_close', 'fbsql_query',
                 'socket_write', 'Manipulation;', 'array_uintersect_uassoc', 'runkit_function_rename',
                 'pg_query', 'eio_mkdir', 'db2_execute', 'chgrp', 'sqlite_query', 'fgetc', 'preg_replace',
                 'get_meta_tags', 'iterator_apply', 'dba_popen', 'runkit_method_rename', 'array_filter',
                 'mysql_unbuffered_query',
                 'ibase_query', 'get_headers', 'fbsql_db_query', 'rename', 'runkit_function_copy', 'xdiff_file_rabdiff',
                 'sleep', 'ldap_connect', 'db2_exec', 'xptr_eval', 'expect_popen', 'ftp_nb_get',
                 'sqlite_create_aggregate', 'fread', 'readlink', 'curl_setopt', 'bzflush', 'singleQuery', 'unserialize',
                 'fflush', 'msession_connect', 'dio_write', 'mysqli_master_query', 'eio_readdir',
                 'imagecreatefromgif', 'eio_fdatasync', 'xdiff_file_diff', 'usort', 'pg_send_prepare', 'passthru',
                 'sybase_unbuffered_query', 'php_check_syntax', 'eio_dup2', 'proc_open', 'forward_static_call',
                 'array_udiff', 'imagecreatefromgd2part', 'yaml_parse', 'array_udiff_uassoc', 'eval', 'preg_filter',
                 'ftp_put', 'xdiff_file_patch', 'parse_str', 'session_id', 'fputcsv', 'imagecreatefromgd2',
                 'dio_read', 'arrayQuery', 'uasort', 'ldap_add', 'event_set', 'pfsockopen', 'mb_ereg_replace', 'gzfile',
                 'ingres_unbuffered_query', 'mysql_db_query', 'gzgetc', 'finfo_file', 'spl_autoload',
                 'unlink', 'ftruncate', 'runkit_constant_redefine', 'trigger_error', 'eio_fchmod',
                 'register_shutdown_function', 'ovrimos_exec', 'sqlite_single_query', 'spl_autoload_register',
                 'fdf_open',
                 'user_error', 'mysql_query', 'copy', 'putenv', 'dba_delete', 'bzwrite', 'rmdir', 'mysqli_query',
                 'w32api_invoke_function', 'printer_open', 'ereg', 'popen', 'gzuncompress', 'register_tick_function',
                 'base64_encode', 'Injection;', 'glob', 'ldap_list', 'ingres_execute', 'file_get_contents',
                 'call_user_func', 'bzread', 'yaml_parse_url', 'ovrimos_result_all', 'ifx_htmltbl_result', 'dba_fetch',
                 'array_walk', 'mysqli_stmt_execute', 'odbc_execute', 'setcookie', 'die', 'printf',
                 'w32api_register_function', 'ociexecute', 'chmod', 'ibase_execute', 'ftok', 'eio_busy', 'eio_mknod',
                 'xdiff_file_patch_binary',
                 'mb_send_mail', 'pg_prepare', 'uksort', 'ob_start', 'eio_fallocate', 'include_once', 'Disclosure;',
                 'ftp_fget', 'array_intersect_uassoc', 'gzgets', 'Splitting;', 'stream_resolve_include_path',
                 'preg_match', 'backticks',
                 'curl_setopt_array', 'ifx_do', 'xpath_eval_expression', 'eio_fstatvfs', 'dl', 'ini_restore',
                 'mssql_query', 'virtual', 'xpath_eval', 'stream_get_contents', 'ftp_nlist', 'eio_custom', 'exec',
                 'ini_set', 'dba_open',
                 'eio_rmdir', 'highlight_file', 'fprintf', 'fscanf', 'require_once', 'array_diff_uassoc',
                 'set_include_path', 'opendir', 'yaml_parse_file', 'system', 'runkit_function_add', 'assert',
                 'fsockopen', 'dba_insert',
                 'sqlite_unbuffered_query', 'is_a', 'parse_ini_file', 'recode_file', 'mail', 'ldap_delete', 'odbc_do',
                 'event_buffer_write', 'forward_static_call_array', 'oci_execute', 'define', 'yaml_emit_file',
                 'preg_replace_callback',
                 'gzpassthru', 'array_diff_ukey', 'sybase_query', 'base64_decode', 'stream_wrapper_register',
                 'vfprintf', 'xdiff_file_diff_binary', 'stream_get_line', 'fpassthru', 'array_walk_recursive', 'gzread',
                 'require', 'touch',
                 'print_r', 'mkdir', 'eregi', 'call_user_func_array', 'scandir', 'error_log', 'array_uintersect_assoc',
                 'event_buffer_new', 'fgetcsv', 'imagecreatefrompng', 'readgzfile', 'vprintf', 'msql_query', 'include',
                 'ovrimos_execute', 'sqlite_exec', 'runkit_method_redefine', 'pg_send_query_params', 'eio_chown',
                 'fgetss', 'ifx_query', 'invoke', 'sqlite_array_query', 'mb_parse_str', 'odbc_exec', 'ora_do',
                 'mb_eregi_replace',
                 'xdiff_file_bpatch', 'mssql_execute', 'stream_socket_client', 'setrawcookie', 'show_source',
                 'readfile', 'xdiff_file_bdiff', 'dotnet_load', 'move_uploaded_file', 'gzgetss', 'array_uintersect',
                 'ingres_query',
                 'ftp_nb_put', 'chown', 'gzputs', 'eio_write', 'imagecreatefromgd', 'php_strip_whitespace',
                 'ftp_nb_fget', 'mysqli_real_query', 'Execution;', 'create_function', 'shell_exec', 'set_error_handler',
                 'runkit_import', 'extract', 'exit', 'msql_db_query', 'fgets', 'registerPHPFunctions',
                 'xdiff_file_merge3', 'socket_connect', 'msql', 'header', 'shmop_write', 'odbc_result_all', 'loadXML',
                 '__invoke', 'fputs',
                 'assert_options', 'pcntl_exec', 'array_udiff_assoc', 'array_intersect_ukey', 'cyrus_query',
                 'runkit_method_add', 'session_register', 'stream_socket_server', 'array_reduce', 'ftp_get',
                 'array_map', 'pg_send_query',
                 'set_exception_handler', 'Reflection', 'ftp_chmod', 'eio_fstat', 'simplexml_load_file',
                 'sqlite_create_function', 'gzwrite', 'transformToXML', 'ora_exec', 'socket_send', 'zip_open',
                 'sqlite_popen', 'socket_bind']
    if param.lower() in func_name or param in func_name:
        return param

    if param.startswith('\\/') and ('/e' in param or '/ies' in param):
        return "e_model"
    if '<%' in param:
        return "jspasp_code"
    if '<?php' in param.lower():
        if 'eval' in param.lower() or 'POST' in param or 'GET' in param or 'REQUEST' in param:
            return "php_danger"
        return "php_code"

        # cmd命令
    if param.lower().startswith('sudo'):
        if 'iptables' in param.lower():
            return "iptables_cmd"
        elif 'bash' in param.lower() or 'sh' in param.lower():
            return "bash_cmd"
        return "cmd_shell"
    if param.lower().startswith('ping ') or param.lower() == 'ping':
        return "ping_cmd"

    if param.lower().startswith('cd '):
        if 'dir' in param.lower():
            return "cd_dir_cmd"
        return "cd_cmd"

    if param.lower().startswith('chmod'):
        return "chmod_cmd"

    if param.lower().startswith('rm '):
        return "rm_cmd"

    if param.lower().startswith('ls ') or param.lower() == 'ls':
        return "ls_cmd"

    if param.lower().startswith('ps '):
        return "ps_cmd"

    if param.lower().startswith('git '):
        return "git_cmd"

    if param.lower().startswith('curl'):
        return "curl_cmd"

    if param.lower().startswith('cp '):
        return 'cp_cmd'

    if param.lower().startswith('sndapi '):
        return "sndapi_cmd"

    if param.lower().startswith('mysql'):
        return "mysql_cmd"

    if param.lower().startswith('curl') or param.lower().startswith('nohup curl'):
        return "curl_cmd"

    other_cmd = ['who', 'whoami', 'pwd']
    if param.lower() in other_cmd:
        return "other_cmd"

    if param.lower() == 'php\/\/stdin':
        return "input_stream"

    if param == '?>':
        return "close_symbol"

    if param == 'COM':
        return 'COM_CLASS'

    if '\\u00' in param.lower() or '\033[' in param.lower():
        return "special"

    if len(param) > 200:
        if len(param) > 400:
            return "long_danger_info"
        if param.lower().startswith('select'):
            return 'sql_query'
        return "longtext"
    else:
        return "shorttext"


def easy_match_type(param):
    spot = ['_POST', '_GET', '_REQUEST', '_COOKIE', '_SERVER', '_FILES', '_ENV', '_HEADERS', '_SESSION']
    if param in spot:
        return "spot"

    if param.lower() == 'php\/\/input':
        return "spot"

    if (param.startswith('http') and 'href=' not in param) or (param.startswith('https') and 'href=' not in param):
        if param.lower().endswith('.jpg') or param.lower().endswith('.ico') or param.lower().endswith(
                '.jpeg') or param.lower().endswith('.png'):
            return "pic_file"
        if len(param.split('.')) == 2:
            return param.split('.')[-1] + '_file'
        return "url"
    if re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", param):
        if param.lower().startswith('\\/www\\/wwwroot') or param.lower().startswith('c') or param.lower().startswith(
                'd'):
            type = param.split('.')[-1]
            if len(type) > 0 and len(param.split('.')) > 1 and type.isalpha():
                return type + "_file"
            else:
                return "default_file"
        if param.lower().endswith('.jpg') or param.lower().endswith('.ico') or param.lower().endswith(
                '.jpeg') or param.lower().endswith('.png'):
            return "pic_file"
        return "url"

    type = param.split('.')[-1]
    if len(type) > 0 and len(param.split('.')) > 1 and type.isalpha():
        return type + "_file"
    if param.isdigit():
        return "number"
    if param.startswith("JPEG"):
        return "JFIF"
    func_name = ['join', 'feof', 'pclose', 'chr', 'ord', 'htmlentities', 'void', 'defined', 'define', 'ftp_exec',
                 'apache_setenv', 'file_put_contents', 'parsekit_compile_file', 'session_set_save_handler',
                 'sqlite_open',
                 'ldap_search', 'fwrite', 'posix_mknod', 'eio_chmod', 'usleep', 'eio_fchown', 'dbx_query',
                 'runkit_method_copy', 'ftp_delete', 'imap_mail', 'imagecreatefromjpg', 'eio_unlink',
                 'strrev', 'runkit_function_redefine', 'ldap_read', 'imap_open', 'print', 'eio_close', 'fbsql_query',
                 'socket_write', 'Manipulation;', 'array_uintersect_uassoc', 'runkit_function_rename',
                 'pg_query', 'eio_mkdir', 'db2_execute', 'chgrp', 'sqlite_query', 'fgetc', 'preg_replace',
                 'get_meta_tags', 'iterator_apply', 'dba_popen', 'runkit_method_rename', 'array_filter',
                 'mysql_unbuffered_query',
                 'ibase_query', 'get_headers', 'fbsql_db_query', 'rename', 'runkit_function_copy', 'xdiff_file_rabdiff',
                 'sleep', 'ldap_connect', 'db2_exec', 'xptr_eval', 'expect_popen', 'ftp_nb_get',
                 'sqlite_create_aggregate', 'fread', 'readlink', 'curl_setopt', 'bzflush', 'singleQuery', 'unserialize',
                 'fflush', 'msession_connect', 'dio_write', 'mysqli_master_query', 'eio_readdir',
                 'imagecreatefromgif', 'eio_fdatasync', 'xdiff_file_diff', 'usort', 'pg_send_prepare', 'passthru',
                 'sybase_unbuffered_query', 'php_check_syntax', 'eio_dup2', 'proc_open', 'forward_static_call',
                 'array_udiff', 'imagecreatefromgd2part', 'yaml_parse', 'array_udiff_uassoc', 'eval', 'preg_filter',
                 'ftp_put', 'xdiff_file_patch', 'parse_str', 'session_id', 'fputcsv', 'imagecreatefromgd2',
                 'dio_read', 'arrayQuery', 'uasort', 'ldap_add', 'event_set', 'pfsockopen', 'mb_ereg_replace', 'gzfile',
                 'ingres_unbuffered_query', 'mysql_db_query', 'gzgetc', 'finfo_file', 'spl_autoload',
                 'unlink', 'ftruncate', 'runkit_constant_redefine', 'trigger_error', 'eio_fchmod',
                 'register_shutdown_function', 'ovrimos_exec', 'sqlite_single_query', 'spl_autoload_register',
                 'fdf_open',
                 'user_error', 'mysql_query', 'copy', 'putenv', 'dba_delete', 'bzwrite', 'rmdir', 'mysqli_query',
                 'w32api_invoke_function', 'printer_open', 'ereg', 'popen', 'gzuncompress', 'register_tick_function',
                 'base64_encode', 'Injection;', 'glob', 'ldap_list', 'ingres_execute', 'file_get_contents',
                 'call_user_func', 'bzread', 'yaml_parse_url', 'ovrimos_result_all', 'ifx_htmltbl_result', 'dba_fetch',
                 'array_walk', 'mysqli_stmt_execute', 'odbc_execute', 'setcookie', 'die', 'printf',
                 'w32api_register_function', 'ociexecute', 'chmod', 'ibase_execute', 'ftok', 'eio_busy', 'eio_mknod',
                 'xdiff_file_patch_binary',
                 'mb_send_mail', 'pg_prepare', 'uksort', 'ob_start', 'eio_fallocate', 'include_once', 'Disclosure;',
                 'ftp_fget', 'array_intersect_uassoc', 'gzgets', 'Splitting;', 'stream_resolve_include_path',
                 'preg_match', 'backticks',
                 'curl_setopt_array', 'ifx_do', 'xpath_eval_expression', 'eio_fstatvfs', 'dl', 'ini_restore',
                 'mssql_query', 'virtual', 'xpath_eval', 'stream_get_contents', 'ftp_nlist', 'eio_custom', 'exec',
                 'ini_set', 'dba_open',
                 'eio_rmdir', 'highlight_file', 'fprintf', 'fscanf', 'require_once', 'array_diff_uassoc',
                 'set_include_path', 'opendir', 'yaml_parse_file', 'system', 'runkit_function_add', 'assert',
                 'fsockopen', 'dba_insert',
                 'sqlite_unbuffered_query', 'is_a', 'parse_ini_file', 'recode_file', 'mail', 'ldap_delete', 'odbc_do',
                 'event_buffer_write', 'forward_static_call_array', 'oci_execute', 'define', 'yaml_emit_file',
                 'preg_replace_callback',
                 'gzpassthru', 'array_diff_ukey', 'sybase_query', 'base64_decode', 'stream_wrapper_register',
                 'vfprintf', 'xdiff_file_diff_binary', 'stream_get_line', 'fpassthru', 'array_walk_recursive', 'gzread',
                 'require', 'touch',
                 'print_r', 'mkdir', 'eregi', 'call_user_func_array', 'scandir', 'error_log', 'array_uintersect_assoc',
                 'event_buffer_new', 'fgetcsv', 'imagecreatefrompng', 'readgzfile', 'vprintf', 'msql_query', 'include',
                 'ovrimos_execute', 'sqlite_exec', 'runkit_method_redefine', 'pg_send_query_params', 'eio_chown',
                 'fgetss', 'ifx_query', 'invoke', 'sqlite_array_query', 'mb_parse_str', 'odbc_exec', 'ora_do',
                 'mb_eregi_replace',
                 'xdiff_file_bpatch', 'mssql_execute', 'stream_socket_client', 'setrawcookie', 'show_source',
                 'readfile', 'xdiff_file_bdiff', 'dotnet_load', 'move_uploaded_file', 'gzgetss', 'array_uintersect',
                 'ingres_query',
                 'ftp_nb_put', 'chown', 'gzputs', 'eio_write', 'imagecreatefromgd', 'php_strip_whitespace',
                 'ftp_nb_fget', 'mysqli_real_query', 'Execution;', 'create_function', 'shell_exec', 'set_error_handler',
                 'runkit_import', 'extract', 'exit', 'msql_db_query', 'fgets', 'registerPHPFunctions',
                 'xdiff_file_merge3', 'socket_connect', 'msql', 'header', 'shmop_write', 'odbc_result_all', 'loadXML',
                 '__invoke', 'fputs',
                 'assert_options', 'pcntl_exec', 'array_udiff_assoc', 'array_intersect_ukey', 'cyrus_query',
                 'runkit_method_add', 'session_register', 'stream_socket_server', 'array_reduce', 'ftp_get',
                 'array_map', 'pg_send_query',
                 'set_exception_handler', 'Reflection', 'ftp_chmod', 'eio_fstat', 'simplexml_load_file',
                 'sqlite_create_function', 'gzwrite', 'transformToXML', 'ora_exec', 'socket_send', 'zip_open',
                 'sqlite_popen', 'socket_bind']
    if param.lower() in func_name or param in func_name:
        return param
    if param.startswith('\\/') and ('/e' in param or '/ies' in param):
        return "e_model"
    if '<%' in param:
        return "jspasp_code"
    if '<?php' in param.lower():
        if 'eval' in param.lower() or 'POST' in param or 'GET' in param or 'REQUEST' in param:
            return "php_danger"
        return "php_code"

    # cmd命令

    if param.lower().startswith('sudo'):
        if 'iptables' in param.lower():
            return "iptables_cmd"
        elif 'bash' in param.lower() or 'sh' in param.lower():
            return "bash_cmd"
        return "cmd_shell"
    if param.lower().startswith('ping ') or param.lower() == 'ping':
        return "ping_cmd"

    if param.lower().startswith('cd '):
        if 'dir' in param.lower():
            return "cd_dir_cmd"
        return "cd_cmd"

    if param.lower().startswith('chmod'):
        return "chmod_cmd"

    if param.lower().startswith('rm '):
        return "rm_cmd"

    if param.lower().startswith('ls ') or param.lower() == 'ls':
        return "ls_cmd"

    if param.lower().startswith('ps '):
        return "ps_cmd"

    if param.lower().startswith('git '):
        return "git_cmd"

    if param.lower().startswith('curl'):
        return "curl_cmd"

    if param.lower().startswith('cp '):
        return 'cp_cmd'

    if param.lower().startswith('sndapi '):
        return "sndapi_cmd"

    if param.lower().startswith('mysql'):
        return "mysql_cmd"

    if param.lower().startswith('curl') or param.lower().startswith('nohup curl'):
        return "curl_cmd"

    other_cmd = ['who', 'whoami', 'pwd']
    if param.lower() in other_cmd:
        return "other_cmd"

    if param.lower() == 'php\/\/stdin':
        return "input_stream"

    if param == '?>':
        return "close_symbol"

    if param == 'COM':
        return 'COM_CLASS'

    if '\\u00' in param.lower() or '\033[' in param.lower():
        return "special"

    if len(param) > 200:
        if len(param) > 400:
            return "long_danger_info"
        if param.lower().startswith('select'):
            return 'sql_query'
        return "longtext"
    else:
        return "shorttext"



def deal_node_list(node_list, flag):
    new_node = []
    for node in node_list:
        type = node.split(':')[0]
        value = node.split(':')[1:]
        value = "".join(value)
        type = type.replace("[", "")
        param = value.replace("]", "").replace('"', '').replace('[', '').strip()
        if '(+)' in type:
            new_node.append(type.replace('(+)', '_ADD'))
        elif '(.)' in type:
            new_node.append(type.replace('(.)', '_DOT'))
        elif '(=)' in type:
            new_node.append(type.replace('(=)', '_EQUAL'))
        elif type.startswith('INCLUDE_OR_EVAL'):
            new_node.append(type.split('(')[1].replace(')', ''))
        else:
            new_node.append(type)
        if type != 'ECHO' and len(param) > 0 and param != 'NULL':
            if type == 'CLASS' or type == 'METHOD' or type == 'EXIT':
                continue
            elif type == 'VAR':
                if easy_match_type(param) != 'spot':
                    param = 'var_var'
                else:
                    if flag:
                        param = easy_match_type(param)
                    else:
                        param = type_file_param_standard(param)
            elif type == 'ZVAL':
                try:
                    if new_node[-2].endswith('_var'):
                        continue
                except:
                    pass
                if flag:
                    param = easy_match_type(param)
                else:
                    param = type_file_param_standard(param)
            new_node.append(param)
    return new_node


def save_set_for_redis(redis_client, data_flag, set_data):
    redis_set = {str(item).encode('utf-8') for item in set_data}
    print("set data serialization complete")
    for word in tqdm(redis_set):
        redis_client.sadd(data_flag, word)
    print("Redis storage completed")


def call_api(file, number=3):
    opt_ast = extract_ast(file)
    if not opt_ast:
        return []

    results = []
    gram_tree = extract_3gram_subtree(opt_ast, False)
    feature = slide_word(gram_tree, number)
    for fea in feature:
        hs = md5_hash(fea)
        results.append(hs)
    return results

def add_base():
    path = '../icse/benign_train'
    files = get_all_files(path)
    # print(len(files))

    # redis_client = connect_redis()

    pool = mp.Pool(mp.cpu_count())

    results = []
    for file in tqdm(files):
        results.append(pool.apply_async(call_api, (file, 3,)))
        # results = call_api(file, 3)
    pool.close()
    print(len(results))

    hs_data = set()

    for res in tqdm(results):
        try:
            res = res.get(timeout=30)
            for r in res:
                hs_data.add(r)
        except:
            pass

    # save_set_for_redis(redis_client, sub, hs_data)

    file_name = 'model/sys2_1.pkl'
    with open(file_name, 'wb') as file:
        pickle.dump(hs_data, file)

if __name__ == '__main__':
    add_base()