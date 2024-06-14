# coding=utf-8
from gen_base import *
from config import *

def calc_word_kind_similar(fea):
    word = set()
    for seq in stop_seq:
        try:
            fea.remove(seq)
        except:
            pass
    for i in fea:
        for ii in i:
            if not ii.endswith('_file'):
                word.add(ii)

    if len(word) > 0:
        return define_similarity_opc(stop_bak, list(word))
    else:
        return 1.0


def extract_3gram_subtree_kind(input_json, flag):
    ast_list = xxx(input_json, [])
    gram_tree = []
    for sub in ast_list:
        node_list = foreach_ast_extract_name(sub, [])
        node_list = deal_node_list(node_list, flag)
        if len(node_list) > 0:
            gram_tree.append(tuple(node_list))
    return gram_tree


def define_similarity_opc(a, b):
    return len(a.intersection(set(b))) / len(set(b))


def predict_api(file, number=3):
    opt_ast = extract_ast(file)
    if not opt_ast:
        return -1.0, file
    gram_tree = extract_3gram_subtree_kind(opt_ast, True)
    if len(gram_tree) > 0:
        similar = calc_word_kind_similar(gram_tree)
        if similar < 1.0:
            hss = []
            gram_tree = extract_3gram_subtree(opt_ast, False)
            feature = slide_word(gram_tree, number)
            for fea in feature:
                hs = md5_hash(fea)
                hss.append(hs)
            return hss, file
        else:
            return 1.0, file
    else:
        return 1.0, file


if __name__ == '__main__':
    path = '../icse/benign_test'
    file_name = 'model/sys2_1.pkl'
    with open(file_name, 'rb') as file:
        loaded_set = pickle.load(file)

    print("Loaded Set:", len(loaded_set))
    files = get_all_files(path)

    pool = mp.Pool(mp.cpu_count())

    num = 0
    total = len(files)

    results = []

    for file in files:
        results.append(pool.apply_async(predict_api, (file, 3)))

    pool.close()

    for i in tqdm(results):
        try:
            score, file = i.get(timeout=30)
            if isinstance(score, list):
                similar_opt = define_similarity_opc(loaded_set, score)
                if similar_opt == 1.0:
                    num += 1
            elif score == 1.0:
                    num += 1

        except:
            pass

    print(num, total, num / total)
