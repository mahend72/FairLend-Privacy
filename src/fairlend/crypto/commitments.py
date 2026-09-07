"""Cryptographic commitments for account/score credentials and application
binding.

Not yet implemented (Phase 8). Will provide ``Com(message; randomness)``
used to construct:

    C_acc_i   = Com(uid_i || acc_i;      r_acc_i)
    C_score_i = Com(uid_i || s_i;        r_score_i)

and the application commitment (a hash, per the manuscript's definition):

    C_app_i = H(uid_i || C_acc_i || C_score_i
                || H(Serialize(Enc.acc_i)) || H(Serialize(Enc.s_i))
                || d_g_i || n_i)
"""
