extern crate milagro_crypto;
use self::milagro_crypto::ff::FF;
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use services::crypto::types::{PublicKey, PrimaryEqualProof, PrimaryPredicateGEProof, Predicate};
use services::crypto::constants::{LARGE_E_START};

pub fn calc_tge(pk: &PublicKey, u: &HashMap<String, FF>, r: &HashMap<String, FF>,
                mj: &FF, alpha: &FF, t: &HashMap<String, FF>) -> Vec<FF> {
    let mut tau_list = Vec::new();

    let mut t_tau = FF::from_hex("1", 64);

    for i in 0..4 {
        let cur_u = u.get(&i.to_string()[..]).unwrap();
        let cur_r = r.get(&i.to_string()[..]).unwrap();

        t_tau = &FF::pow(&pk.z, &cur_u, &pk.n) * &FF::pow(&pk.s, &cur_r, &pk.n);

        FF::modulus(&mut t_tau, &pk.n);

        tau_list.push(t_tau);
    }

    let delta = r.get("DELTA").unwrap();
    t_tau = &FF::pow(&pk.z, &mj, &pk.n) * &FF::pow(&pk.s, &delta, &pk.n);

    FF::modulus(&mut t_tau, &pk.n);

    tau_list.push(t_tau);

    let mut Q = FF::from_hex("1", 64);

    for i in 0..4 {
        let mut t_pow_u = FF::pow(
            &t.get(&i.to_string()[..]).unwrap(),
            &u.get(&i.to_string()[..]).unwrap(),
            &pk.n
        );
        t_pow_u.set_size(64);

        Q = &Q * &t_pow_u;
    }

    let mut pks_pow_alpha = FF::pow(&pk.s, &alpha, &pk.n);
    pks_pow_alpha.set_size(64);

    Q = &Q * &pks_pow_alpha;


    //there is problem with pk.n big counts
    let pkn_bytes = pk.n.to_bytes();
    let mut module = FF::from_bytes(&pkn_bytes[..], pkn_bytes.len(), 64);

    FF::modulus(&mut Q, &module);
    //////////////////////

    tau_list.push(Q);

    tau_list
}

pub fn verify_equality(proof: &PrimaryEqualProof, c_h: FF, all_revealed_attrs: &HashMap<String, FF>) -> Vec<FF> {
    let mut t_hat: Vec<FF> = Vec::new();

    let pk = mocks::wallet_get_pk();/////wallet get pk
    let attr_names = vec!["name".to_string(), "age".to_string(), "height".to_string(), "sex".to_string()];/////wallet get attr names

    let attr_names_hash_set: HashSet<String> = HashSet::<String>::from_iter(attr_names.iter().cloned());
    let revealed_attr_names: HashSet<String> = HashSet::<String>::from_iter(proof.revealed_attr_names.iter().cloned());

    let unrevealed_attr_names =
        attr_names_hash_set
            .difference(&revealed_attr_names)
            .map(|attr| attr.to_owned())
            .collect::<Vec<String>>();

    let t1: FF = calc_teq(&pk, &proof.a_prime, &proof.e, &proof.v, &proof.m,
                                            &proof.m1, &proof.m2, &unrevealed_attr_names);

    let mut rar = FF::from_hex("1", 64);

    for attr_name in proof.revealed_attr_names.iter() {
        let mut pkr_pow_revealed_attrs =
            FF::pow(
                &pk.r.get(attr_name).unwrap(),
                &all_revealed_attrs.get(attr_name).unwrap(),
                &pk.n
            );
        pkr_pow_revealed_attrs.set_size(64 as usize);

        rar = &rar * &pkr_pow_revealed_attrs;
    }

    let two_pow_large_e_start: FF =
        FF::pow(
            &FF::from_hex("2", 32),
            &FF::from_hex(&format!("{:x}", LARGE_E_START)[..], 32), //LARGE_E_STArT to hex and than to FF
            &FF::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 32)
        );

    let mut aprime_pow_large_e_start = FF::pow(&proof.a_prime, &two_pow_large_e_start, &pk.n);
    aprime_pow_large_e_start.set_size(64);

    rar = &rar * &aprime_pow_large_e_start;
    //fine -______-

    let pkz_div_rar = div(&pk.z, &rar, &pk.n); //need operation div

    //14e1f102d149d5c026475fe149631a3f578b00e07dd431eccb75c8e4d5dd0b4fe121057f60e090fa1da81f37f6c9b87f2fe4ad352735d42b351c5fbfd97d1c37e283d66186a7b4dc6638e31ab033cc67dcd115a031804863213ea7222ef0b810414a4cbed8c3c30c8de0626087c94d26c9e6266a0ceaee74bda49fbaa14aead19d8010c8ff24581f0921d0f486012a620eaca9a4370f0f13d4dbab4533fd467175561c5a99dc6066764e7fc35430695d4ee71e23a74b934625a51f67d5d034623f9c378cb61fee376234af9e481e0c753be47fddab3eb04b2b6f624292b14b5c170ca479d9fafd56ab954c3f3a3c8a01709f6752b1492fcd2050e1e1838f2efd

    //        let neg_ch = FF::neg(&c_h); //need operation neg
    //
    //        let mut t2 = FF::pow(&pkz_div_rar, &neg_ch, &pk.n);
    //
    //        FF::modulus(&mut t2, &pk.n);
    //
    //        let mut t = &t1 * &t2;
    //        FF::modulus(&mut t, &pk.n);
    //
    //        t_hat.push(t);

    t_hat
}

pub fn verify_ge_predicate(proof: &PrimaryPredicateGEProof, c_h: &FF) -> Vec<FF> {
    let pk = mocks::wallet_get_pk();/////wallet get pk
    let (k, v) = (&proof.predicate.attr_name, &proof.predicate.value);

    let mut tau_list = calc_tge(&pk, &proof.u, &proof.r, &proof.mj,
                                                  &proof.alpha, &proof.t);

    let neg_ch = c_h; //FF::neg(&c_h); //need operation neg

    for i in 0..4 {
        let mut tt = FF::pow(
            &proof.u.get(&i.to_string()[..]).unwrap(),
            &neg_ch,
            &pk.n
        );

        FF::modulus(&mut tt, &pk.n);

        tau_list[i] = &tau_list[i] * &tt;

        FF::modulus(&mut tau_list[i], &pk.n);
    }

    let pkz_pow_v = FF::pow(
        &pk.z,
        &FF::from_hex(&format!("{:x}", v)[..], 32),
        &pk.n
    );

    let delta = proof.t.get("DELTA").unwrap();

    tau_list[4] = &tau_list[4] *
        &FF::pow(
            &(delta * &pkz_pow_v),
            &neg_ch,
            &pk.n
        );

    FF::modulus(&mut tau_list[4], &pk.n);


    let mut lett_v_pow_ch = FF::pow(&delta, &neg_ch, &pk.n);
    lett_v_pow_ch.set_size(64);

    tau_list[5] = &tau_list[5] * &lett_v_pow_ch;

    FF::modulus(&mut tau_list[5], &pk.n);

    tau_list
}

pub fn calc_teq(pk: &PublicKey, a_prime: &FF, e: &FF, v: &FF, mtilde: &HashMap<String, FF>, m1tilde: &FF, m2tilde: &FF, unrevealed_attr_names: &Vec<String>) -> FF {
    let mut rur = FF::from_hex("1", 64);

    for k in unrevealed_attr_names.iter() {
        let cur_r = pk.r.get(k).unwrap();
        let cur_m = mtilde.get(k).unwrap();

        let mut pkr_pow_mtilde = FF::pow(&cur_r, &cur_m, &pk.n);
        pkr_pow_mtilde.set_size(64 as usize);
        rur = &rur + &pkr_pow_mtilde
    }

    let mut pkrms_pow_m1_tilde = FF::pow(&pk.rms, &m1tilde, &pk.n);
    pkrms_pow_m1_tilde.set_size(64 as usize);

    rur = &rur * &pkrms_pow_m1_tilde;

    let mut pkrctxt_pow_m2_tilde = FF::pow(&pk.rctxt, &m2tilde, &pk.n);
    pkrctxt_pow_m2_tilde.set_size(64 as usize);

    rur = &rur * &pkrctxt_pow_m2_tilde;

    let mut a_prime_pow_e = FF::pow(&a_prime, &e, &pk.n);
    a_prime_pow_e.set_size(64 as usize);

    let mut result = &a_prime_pow_e * &rur;

    let mut pk_s_pow_v = FF::pow(&pk.s, &v, &pk.n);
    pk_s_pow_v.set_size(64 as usize);

    result = &result * &pk_s_pow_v;

    //there is problem with pk.n bigs count
    let pkn_bytes = pk.n.to_bytes();//there is problem with pk.n bigs count
    let mut module = FF::from_bytes(&pkn_bytes[..], pkn_bytes.len(), 64);

    FF::modulus(&mut result, &module);
    //////////////////////

    result
}

fn div(a: &FF, b: &FF, p: &FF) -> FF {
    //(a * b^(p-2)) % p

    let two = FF::from_hex("2", p.len());

    let mut p_sub_2 = p - &two;

    let b_pow_c = FF::pow(&b, &p_sub_2, &p);

    let mut res = a * &b_pow_c;

    FF::modulus(&mut res, p);

    res
}

#[test]
fn calc_teg_works() {
    let proof = mocks::get_ge_proof();
    let c_h = FF::from_hex("1066d2487a484fd43ad9f809a7b694bcf98dd7e9876173674e2573dd1152860bfd98cbb827794acac2e1546114fe85b2efb09f6cfb6974694d18822df221d7bb560ad1c810c9a58f8a55", 32);

    let res: Vec<FF> = verify_ge_predicate(
        &proof,
        &c_h
    );
}

#[test]
fn calc_teq_works() {
    let proof = mocks::get_eq_proof();
    let res: FF = calc_teq(
        &mocks::wallet_get_pk(),
        &proof.a_prime,
        &proof.e,
        &proof.v,
        &proof.m,
        &proof.m1,
        &proof.m2,
        &vec!["sex".to_string(), "age".to_string(), "height".to_string()]
    );
}

#[test]
fn verify_equlity_test() {
    let mut all_revealed_attrs = HashMap::new();
    all_revealed_attrs.insert("name".to_string(), FF::from_hex("db74c940d447e877d119df613edd27", 32));

    let res: Vec<FF> = verify_equality(
        &mocks::get_eq_proof(),
        FF::from_hex("c7b01d94ee76cc411a4a818107fdb3b331fec5f3b6a77af52d2051dcb7a5718a", 32),
        &all_revealed_attrs
    );
}

mod mocks {
    use super::*;

    pub fn wallet_get_pk() -> PublicKey {
        let mut r = HashMap::new();
        r.insert("name".to_string(), FF::from_hex("1b8babcacb5182020e0c04b9b49bc8b94ce57d7902ff3375a406fa1b07aca6076c1ef637229f24c4f9ac5a1bbfc465d085236a09fcec797187b9eaeec97cb24905a618e9e868cd5addf8444735d8c7c50d510fdbff1123889cf8ca5576f3db67836fa412ddd225316d0176f9b8f380516f39477fac70e09c15dd37d689d1277c38989fae60013f6dc9dfd6942050d391c496666479f7473db6df0ae110be596721ca2d60dea6d3bd8615723667f996bfd7100a8013a59328494c11e14eb348cc191a6c71ab7a3ff51c3c4f4bda3a1a0e25e6704f687cd3f6fd3037182115e34e3651cd3ceeec830539c20064fefb28566d686794a22d73d389add8015046c3b64", 32));
        r.insert("height".to_string(), FF::from_hex("fd99f2f56efdb2ed83298b4c52abc7308a7b60bef2f7a0f48a958130b58c9ccea8b0f0d55333ca5be20716342edb86c447f7858e75e10462f3e02c63f603f00e19809275f719f0c215ae83db27cd074ea91e7dfa65539ccffcd7cb0e0d1bc93c36da12f7f66eba24ccc3fbb2c120809d75b7ade620c9939b48afc1b65012c501c07afdbac1d3d115d6a9514ea4e228f60db43b5784881ec815f3732c963f4f7ce1ea2f6884192b2e933edefdbd637204273bec122cd39591eb166ff9ef81abf57a0ec84ec2d2c8f9e46fba136bfc0a048a676717697430128336e32b1b89435ca357a73375b39fbb1b6c5ed1a274a52dc8162e8d821a362a0595b0daf19d871c", 32));
        r.insert("age".to_string(), FF::from_hex("2c2758078ebc8be4c0644af3742e5dd6b83c6c4452eb4ac0b539333fbbecf9950b175bdf331f453f533f82a9ee585754bd429ba0363489ea0ca8febc08ab27e726bd52aa855fcf35d49a299bd2ded122ea20bb2ee439de02566958a54aa6bb365d7f04be1366f4424b74128307d719df6f2f8671d426fe4dce066a216de4c83c83c2b1cf2f1e58592b6c7984d0bc263bd3335ecefaac860d4b4593ace338d35a6e8c46bae2e01c7300fa304f73995a42d4f2c15025d27ecb9a83f7400879ad08f575bf9519f2f0a18e08a7870832167a4332dac3645102ccfb84fe3d97c1ad95c86add560621f491201672ffae58574a2f0723fad486c344638cec43efd1d805", 32));
        r.insert("sex".to_string(), FF::from_hex("15f1332c6649bfeb77ac6e2bcfd114c4655ebfb9d2b1b2ae1c9c43d8a1f2e40e5a93896881725d789909126b11c16027baec8f1cc755691ba7b515cd73edb82f09c17972e6e6d38498e1433d54bf42709b41d7eaabc21b94b01a3457711b2ae539950c2d4abbc14d2c223ad8e36b3b87e06a2a42a9b79217fbd59a4d0e3ba1f2e545de58b7d42dfd4b6f65283edaf3534fe5dc61e35d4a0c1f461c9b0c58ed4c71686a23f3b2c9acef57161054973e6d685dcd378cb5ffd93da55c5ab92dda6f02355f8d0588fb56e0cda7688c7bc26d153de6115f64b642f924be2f0934472ba89937c43f81bdfb804bf6636ecd94301b91fe8c8f020e4985660179f1c9a8bf9", 32));

        PublicKey {
            n: FF::from_hex("2f25fa4163e25083717f150b16229c2fa57d56dcb5048c522a64251a23e03342d0772b46cf47fc9e66e705b1910be1b968f45af1e6ff1d95fe1e319bec7dc34f60e33a664ab202afbe4098f09aa7f9e233a82ac0c1958b900c2a7b26f8dce2ebf774b35acfbf9a87f682498d5913d476300a558cb536c8facc9ef6f7a8a8925cfae17f913cddc9d4582c9dfca648ad074f88113f261839c4342fa8f33653979582d7d4c0716fe892371161712f8b77af31545420d6f075474f8847dddc2821b32125fba3807957e05218e655f5a8c8e7b96f1e1fff38b9177ef81e30ae3cacaaf64e5987c2fcfdc197ac2e43800acf3709ae381b0196f1a1bff153b6e93a4088d", 32),
            s: FF::from_hex("2964f0b14716e819da4fbaa6abbaeced56471ff859bcaf6dc7b7b8ff92981e23cd20ed67adaf3b3a57dc772aaa28716db2e8a885b529b06b2176fbd138e2bf54719727f011cd0dcdc80f45a352ea1c8f317857370e8948f8b73d2d06ddd900b3cb8527e269ee184f7d2ef9c50c4ba769f23a9ad7838fd48266ac834e0de30fef6bf55ba801aff3bc0b2e413e7089ff0896d4eb2b676da6a04ff7e7460371c4a7f55381c116baafdf23a4a4899ab9c769334704712feaa4fff24606af98c2502dc6e1fe075cc56076665a47bcfeb3c0657796e65e0c57fd59e9bf78f5d5ceeb10f109f76e87c44142562ef9ae9d444c9f05f8b39c919dbcf707ad1873f1c555f2b", 32),
            rms: FF::from_hex("5f13d1162a2e4242437428b697fd18643532ad38baab29de02083f91c4a860fe0929c53ba51820d42d79479a31d4d61fd523ae4f77dca41df8e7141e91436d410efa49066c423b36a263c5d200bcaf03e3f35bc9da9ba9af9f24c34e4732102d4789061ae0c2f2f4b486f4f7cef7f858edf5f6fe14a033af5e5c9b4ef50e3b2e79d72b135e3defd8167052e2785647442c86c294692bb299de22b9b0fe842d31441a138d8ad0ebd7c225ad3a1078109e1b53e59436c7bd8d28b4768cedba031db0b1600633c0806e875ea84a9d123c0efb3f3c1a4b69e39ae53e174a20c1e34e7e0ef5ffa877f2f27b39c2ecb87fb33c585f2c04849fde795599477b7af2f4a0", 32),
            r: r,
            rctxt: FF::from_hex("262faf605951ceaaafa3aeccf7a97fc987e36611f93bc51e8aae92f065c45e96ab181a089e5aca9136dd90ef63a7fbccdf60393de176fba0ba96e4c20d5095140d775eae7b1026c01c05e65ed299537114b3d421409c1ca987c958f772c5c35b06dcc13349eb382257f43785d243a3b617eee42656e50aad00b8448bdfd0a1fc3300f43dd2caf560ad66c11eea31736b2154ee6a11d9cc2a534ac94e1f37aad54991da48fefaa689b9f4a296e24cead07959adbb7e1c3dd326a482753b3d243a07825df2f00b24d5866af815c8f6ec16066e2cdcd7503ccb40b6c1cc2975b20d96db7b307b2eb1e9c4195cddb07339b11a9ba2655cefdc6d68fe76995e5ff860e", 32),
            z: FF::from_hex("1b4fcc44dd0a81647c21b739300277053595b1dc731649d19567911be768a9ba7de536b1ce4d455434b617acf432e2901a2977fbee1bff419abf5d67783612c0e4e75dd1626bf7d78af4c9ce1e22e6494d95f70e1a1965db63c5c188bb33ceace744eb10b4dcf7db10724429c973f9c407a9fb9ceadf5d6be26afd6cfafcf626710a05c05e176406b068fa627ce1ea4069228bf709173e17244050db1dead61119836e8db3b2c1581909d44eafa191441f7f60f58b503f4348f118e3ae7a1d0164204ab2311791dc7cd7e7d87ee885aec0a52aaf69f6a39e9fb127d9c26322f6e8cbf56b98f9e10a74a65f5d2180f3eaf7e62db6fbdaa074d68a657fcb23b563f", 32)
        }
    }

    pub fn get_ge_proof() -> PrimaryPredicateGEProof {
        let mut u = HashMap::new();
        u.insert("3".to_string(), FF::from_hex("8e00683961e2083221e04700bbe71cfafe0c7269fc18297ed5aa4d8626872b3df33dd819b157392b8c6299e7817615dfbd376489d003a0f2d572ca09527aacbee0c6e150ab357dc597b9", 32));
        u.insert("0".to_string(), FF::from_hex("31437ab9c4b332dfececf0bbcf578fc55cd7eba8076b866e802e2716aa65a5e5a0248ac6ddf9a635766534f4653fcddfa5ecb787439360ad5eb380f2ea3374c0856712aa8a92f5f5864a", 32));
        u.insert("1".to_string(), FF::from_hex("f515fcac998297dd945e10b3adea655c1931fe0b16ddc4aa1c8210aea6f52b6f3bd09b2d7b8aba21a2199f6d4389108bbbe9bee17e89162c0ff251ad9608e704466fb99667f46b1cf56a", 32));
        u.insert("2".to_string(), FF::from_hex("ea262afa9122ec5cdf36c4466725140d6ee443b08f167c021d19dd0e93eb174661f6a51213f85a914bd401a5670f593d8a6f429ae2beff574cab8a134e795fe5be8c4159d36beccf5d6f", 32));

        let mut r = HashMap::new();
        r.insert("3".to_string(), FF::from_hex("4211fb52737f586b9e9fc1e6731713e30fab37bd9e4ef178de69f147534bebac56640a7bb1d6167cbd101f6555053c7c56d6241564aa0dfbacb0e7b6b93d99cb9e43069f8a4960fcba9e2f390818ede4f6ea4b8267ca69a32de119885ef378689b6346c4220048e9d9d859aa6ef6aa908742b179d77a46f985a153593ce1e741a082e32fd11018b5f5201a879a9f6b82b6e63e04c3e01c6937f9dadf31dad0f6c9a11038d83e5ae5614f28db2d3d998bd1d41722ff78a3ec6802671f9019f27fe14fb7634bffd051a16e5250e7b0ca979568045f56322f1a6f57b0dbf9038fb139e94fcb0eccc7a2b1b5053fccab5a449dcc8d00b6f1d4aebb1dde5e4a6b5f437c573c71af27cb4d68565f471ba506b8a811f3da4f8653cb151f3e96eaad3901ddd0e6b653e6994a6c59", 32));
        r.insert("0".to_string(), FF::from_hex("7ae129fdcc88816c02946218e53514b9c3a565a380ebd5e1e3906be52dc7a7aa8220bdae4b6ccfba9ca36f53fbe591f8a9f647493fa5959210b7a7674dd40fdcb3aae741a70a51026507d777a6af7b8ea99de67bde69c28a2d2b84a07c92e368d58937c1d72e6aad5b79e3038277ff7f8e7bf69d7413410a8b7d790a11bebc60016c0d3674b092d2324e12914e176d5765232103fef1badc7cb1228c7f8075a6045750ede65fdcf8cbe7af9189f7a31c487a0b17503be60f45bc3534f30c5f1f07eaca7d14af247091e1268b0de132ee407cfc28c0e98a586ce9a737d31f2caea253bd44c2db052532b70f228ab70ca416f2c4529284a8f786066e4e9014e284ab2a423d4d696420b0c24a396ce9b0216c19ca8faf6a4d393a2cdbe6b42b3780e7ba65cf561446710b13", 32));
        r.insert("1".to_string(), FF::from_hex("c0d403440dc1ed3b2e4a0c3fddc97d716f8a8ee55ccbf4ad30df6fd8a7d81a5e4d70525711a68713b833bb4a348dffbff75b134a12fbdefae0cae97813a1a900a00b2c1179e1e705822f96e8e5c2c4c2d3a65c2133f565a86004a5c6230a4f53d905fb8bfd61f0cdd31b64bb2f9e4e2a7cd2b44b08780013438e6bc95b6615ac83170c63e034bfb782388cdd53ba8922a34c6ff50af94bca259b67b5f815998b9e2e88844cf8c6fc997893f8c5f9d9b459e91f0cf103f2015cb1fb96e06fb9f11deb2d052a51bd8c9f3433b78729f2a6c5f8899c6a6f1a0b7c0a04cb61167d6cf63b6ac8229d073fda093e886b1844ba08367aec10835263a701a33d051b5527ae987312a55cb45c43839102eb11b885385735dd79a6d0af001d9c7a7bffdb7a0dc655d95f6bacc03774", 32));
        r.insert("2".to_string(), FF::from_hex("154fee26caeee3ea0beedcb59383422e03ed6d3672fbc1c37bf6bec5bebe7778468e5fd88623bbe14c86f104dc4b1ca2a7e9af63df61af9272724b3268d818823cf291e3f865a587bd5de5e8c0bc8677d8efe86d581d0221e3a07cbc84587ec39c3072b0fbbb8542b0336f163d7604f93a5658c7ce6ab87888ae2d5f0bd1e80aa31bcc963dac204f36f335a97dbb733874101b6eb1b53c6cdf72f754083af77cf7f76c5cadbf9aad7bcbcdf76215ec5316409a62a06d30aea9ee314a6098dee2a6436670237e8be12e227662fae276989d11056a4d185b6e4fd549c7b5cbf035f5e774909289c983cc0abc0bcbf997870809b9ed9f390a30e1c640e695142ff651e7c3e355afc3848fd4ed2db9dafd0e3036c6297b12e6b84a23837fedda168548b132cb50bcc0415f69", 32));
        r.insert("DELTA".to_string(), FF::from_hex("442a5e83dc3a6530b95dc2e86d471235dafd7837eeb7defcbd3f96b9ad0f3d9c2d3a661a6a9cedd89af494fd7a9242e07e632645eee4510ba6dec70ddf92cb2913e9949f916696a91043eb4e821f3727dd4ddac14b267d54bb858309a79c4663b66cce140e0d642950f7eea87fe3700ae9d329f98c606224c0d309f86ef0d188e5365b4d4dbd9e8433dba742c74288164b06938e3c9354b4c4aa6fa39b659a566a18c0fb8a427b19394be009dbc2bba4246f70fd3ab1dea3c6c47bb923ccc00f351157a2236b0ad43c8198f18390a4e47c4338ec9d4be1a9589b3a7eca81a3efecc29fa34c08c41c0e58d435499563a55bcbf392572cac134eb6b96f314ba216be55b64be18c3f062611a5a6bd35a1d6bc9c064a799230f47e0245152265020dc244198974c5322e2d40", 32));

        let mut t = HashMap::new();
        t.insert("3".to_string(), FF::from_hex("29814d72730f86b64e91b25f7827756bd124c76c672b84c0761604a14450525969a870cf3a13f6f1f839253802d17431c2f4371519284e4f5b8790ffe1e32ced685864d00d525a19886f734fbb1a06bafd87f33daa55a314ca1ca65e8d807087dcc072c6c814a0695590950afadcd2979baad6b693b05ec042dd3d59e3da80f1caf16f2506c32c13ad689ba50204cd079e49f5104349d28eca3b2d23834532b1f23e8723eed3076b6def2f80e6d47056f7f504c3cc8756ebea5a4b6c1706231f231cab6a2e5ae09a73bcec03ac5875f749b769bf67c7a90e713b0a6bf8ae8bb66b9365bf9d8851e79c2b34a5f54d42ee4b6f04bdf1224f91a3c1dcb19d17df96c", 32));
        t.insert("0".to_string(), FF::from_hex("898b4891766f25af47c53163853f8588430a7bba2e7ed444dda71e3e4e70f33ad3ed92e2e22d639913646f913ae74866b80a388fa476ff549b31a3dcd83899fc47bd47a8f694dd321d1c2f199f8ccf968dea3bd8a959fb5dd583a93a79b77246cb46e98cf63aa6cf5f02ffe089df49185fe8f23e987f82b11cfe1e06a07ebe6fca2c45a202827d60b97b02a120d645cf966065e1dc19fc1f113723823de96320b5e4639dd1c35fc3ec2300e7e00b447a188fe14e2ae9f96ebb9cfe8b21c2034911531859a524a82e530a0ea5cdda8edf6c989574253b77189738bd2c6b2c4e1fff28c5147b7ad412d3ea97c0a8ced8476204706a1fd840cefbcc4923a5183cd8", 32));
        t.insert("1".to_string(), FF::from_hex("2c4a013cc8af74fa8e57cfea1e5a6363c386e45004276d3a8ba74e9f6de1873944cc165e778728743a6b0c42a1104d987ea70c249f9cec7a315b4fa1fe7c0c0b7b82588ec6465dce8cf4bfc2a7acfbbcdf2d40338353d5c2ee418e7309e1e299908d3b6a63414bbe30eb3e4aa82e36d59aeb09a7c5007c7462f44d7ccd518e30fe9221e53c2ba81acb23c909f638d3373651c32a2d00b3c9c0407546b47629cbaa02678a777ef2794f5c79c5979c459cf10cc86495e2db462f29aa88053dfc17f885c1abb2855f30417f6d18d19575fa150b248d2b7d193395ae8940d64902f4518acdbd87d94f147838466a778e70f638ee226277bd4f197ca231d246695c319", 32));
        t.insert("2".to_string(), FF::from_hex("2c444067ab7133645e52ff241d9db169fb67a942ad31d04cc7d763e0ef3d76d8363a3898044a78b6024afa4614cfc0a78362c8a88db0451284178116d9f13177e9ea6dc5920f9ae2520add01e6567976a14e449cda20c003fba9774b8e7b40ecf36b6d4dfe911d8ae0d319aa4e1aa92df1b19a28cf09bf394bacf24d70fcb232f21e0f890293a6a9a9df2ef449d5c37739c3e12bc65c977225909e0349126603e6a2075fb3eb66c5c6a76fe35dbf080706422236694abb56dd3b268d8fe9d46048181b8801b59d716d311b114055e78df9014353255dc5dc1fc7c425512b0e4771a297f40f53b818cec26bc7acad71156cbf396563469c72eab053ddd65dd12cd", 32));
        t.insert("DELTA".to_string(), FF::from_hex("8adfe85b286580fa5d36619b28b952921016175f22c6919aef0ff6f9c832a5c542326767ec59b234b632983a853fd6219e755bd5e35c7ed46dffebf5b895f8eab42418a845702be9076d77830715b9782cccc541fdd19aa92d9a199cf7692543a4d4ed2b58286638f02cc6c99c2058301b88115142586d2c4782c4e77571ef38b875168c79e46cbb84fa4566ea96365a0b6bdcddcc94fc75eff6fac19ed383ffd38f69d5cb412addc91db217f3a642672f71e096b267c6dab9a383817a849a4a7ebb6162327002f13128ebf27a1b28d8586d863ea1cdaff109b1798a00d71c7928a1bcdee96a41684958914cf301e2cf9ae2b3a37dbb4dedcc2cde8651ea16a9", 32));

        let predicate = Predicate { attr_name: "age".to_string(), p_type: "ge".to_string(), value: 18 };

        PrimaryPredicateGEProof {
            u: u,
            r: r,
            mj: FF::from_hex("1952ed63574e45e977781289154fffad9e7dda1eb6d99d7a478b2f63a27022651c8d06c9d74dafb152d0aaaa66638036feceb244d7ca61b4bd84fc1c8aca21f0c805e60261523066f741", 32),
            alpha: FF::from_hex("e2f4942a6b3333846609ee66f4b5f9f4d111f7ee6c62335f968770a78f5cf9061ec13847d8e75ef094c68b665d83409c0fad520b51168609cb909d84787a1c169330494e1cbd0fbae3fe94cf339ea98e575bca53756bcc5fae3e01802a62526f5a3bbfc2b0ab380e66d2fdb749578b170bc5e7736cdaabc847260827a655617756cd715a495fd8b814b815dbf82401b2ace33c53a819736b1ea04cf262ac35f37cc33770f01d941b0f0f6f6b84c0c01f8cf51d2a55119def9275b864aa7ed523cdb388c21d04bb2619abf067dfdbe559c88ec249b2887779e1c96de8f9b2d8caddf2b2fececd83221665d0b803169d42a393eef5cc6232e52c8ee4e45c901f9b1df00ae18f80f83d9f47bd2e58d895cfbcd01bfd161a71269d4e569772564012d03b4ce6ed8f7b7cd5d7d8a02d8210c2a26a7ccb73721b386ccb3350db3912bb13adf41550af1cede5afe78918c1e9b3e2ea9cc5c1adbe96de820228", 32),
            t: t,
            predicate: predicate
        }
    }

    pub fn get_eq_proof() -> PrimaryEqualProof {
        let mut mtilde = HashMap::new();
        mtilde.insert("height".to_string(), FF::from_hex("3549957cde04217c329b319d54a18952bb92a8d7c0c2c15c5e9fd7ed7b4eb83efbfad23a31f201d8fbae6f67152d29c9b61eb75a9855de5cad808ba339217508c09bf157452aaa6fc1fa", 32));
        mtilde.insert("age".to_string(), FF::from_hex("2f018037913ea0c38793ececf8a71401d963f74bd923a5bd0e782db3e9a3b9fbdf2c204cf61b4428323df6eb7426aa6a83273b040bc842b8283a030403f9c7312792641da150c70b1843", 32));
        mtilde.insert("sex".to_string(), FF::from_hex("1066d2487a484fd43ad9f809a7b694bcf98dd7e9876173674e2573dd1152860bfd98cbb827794acac2e1546114fe85b2efb09f6cfb6974694d18822df221d7bb560ad1c810c9a58f8a55", 32));

        let predicate = Predicate { attr_name: "age".to_string(), p_type: "ge".to_string(), value: 18 };

        PrimaryEqualProof {
            revealed_attr_names: vec!["name".to_string()],
            a_prime: FF::from_hex("270922f1a37a893c3af86085ec0f8b07bdc3b5383047230aeca99f01739addba1acc8b12b329fce92d4b350cad28831c2fa4c711094b815873977201026b57e82298f6d953de95e16192004160b2e97645202d8c33f0d054124550aeb15e7647f762194b32d6e101d1efdb5a0afbb5b31d4baf03acb6e9f5f023002a40edef89a556d1a22f60b5a614c0468caf9ddc055dd633aa4c9d963f20f16d5cbd76c0039dd9c34276e049e53cb296d0f16c86dbf9872c866746476fe5854ee0c6deef01659a4ff3c4d2fa2a17b68381363e4d026b83bb2c3668440163cc99e0eede7c543fed670908409cf103aaad5676153659aedcdbe974770d69bc0af2dee71155127", 32),
            e: FF::from_hex("d84b55034b84daf8d48b4fda6c4cb3a56f9d881d0af52076eeadb1f5f00e63de33be0276e743e85676df4af89261d69ec66d6498b09a382771", 32),
            v: FF::from_hex("e7eb4ae019dc16eb04911666a2aa5624b8aca9c44114072e76efa13eb3625ee7061db4980b40930225bf4cb3c9d13d475209fb79842aa64443babd661fe343bd1b1a7db44694a8f5f77157e8d84c4da3a0b7d91af85f7efa7a0824594b2ad2e7a1d9ad0d6e3143944a5cc7db8772f42d639b130d79724412b1b8c4a406cc071bc5900ef5a973d8d107396c020c8dbe184ef4a32f6b8a6a6f12e49ca3f7354af898f2ad720cba1801fde4d93412d0942c1f4e5528cc28772470ef0edb99aecff216a18118683b65accc13f5ee534fcfdb0d99a61828f4db68165585d9d7830550a478da853eb562c3f8d5760b89d80f3feb3b3cf3433994ed67f41ceabb12fe0dc3a4dcfe9d223a767c9d69474b23e19e39b07be97d735da3d03287d93cec1a89321491b94448c7d5492d00c944d481a32fb961544c7f2b2201363d538ab5daffe04bcf3fc05f72aa1747fa33a6cd38c2de59d4c5a994fafeacf94b9aabc0529a5b06e853cd762437605edd03fbda479dc8c46d6776968642b9d3ec48434d6", 32),
            m: mtilde,
            m1: FF::from_hex("a226a06ec4b728326c3e6bf5b9512e273cfdbb4c382495264d0bbb884cf4eacda1e70e97f4ff07f476f1b4c20bb64989055877733d28acf88dc2c03de4eb558ad1b23cc0d4e779442fba0fafe376bea7c08d933b586eb970019dcebccd2d2467d2b66bdbcd91a8e4b4c6991dc5beda0f85df04bf577eef786f6812c616816faf", 32),
            m2: FF::from_hex("1e2964ab5186204c36316b8bace9369e54cfebec08642da00387c91ccf4ee9c4df0e79d612aad73f3b82bfde72c8ecd8792c2f57a2c70cb30b3b5672a2f729c812250cfd5b599f82d21ccad4281147684f862a1ccf76fbc63828bde185af6b863508785ddc4241b09e6cff809aeadc25116285d2598a972680f1e841b9fbdd5", 32)
        }
    }
}