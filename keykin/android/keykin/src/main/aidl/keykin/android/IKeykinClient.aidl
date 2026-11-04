package keykin.android;

/** The main process, as the signer tells it what changed (KeykinClient). */
oneway interface IKeykinClient {
    /** The memberships on this phone, by slot. */
    void slots(in String[] slots);
    /** One membership's public state, as JSON (KeykinService.stateOf): never a share, a key or a seed. */
    void state(String slot, String json);
}
