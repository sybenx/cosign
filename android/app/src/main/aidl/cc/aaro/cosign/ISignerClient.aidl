package cc.aaro.cosign;

/** The main process, as the signer tells it what changed (SignerClient). */
oneway interface ISignerClient {
    /** The accounts on this phone, by slot, and the one on screen. */
    void accounts(in String[] slots, String active);

    /** One account's state: a serialized Ui with every secret taken out (SignerService.forUi). */
    void state(String slot, in byte[] ui, String label, boolean needsPaper);
}
