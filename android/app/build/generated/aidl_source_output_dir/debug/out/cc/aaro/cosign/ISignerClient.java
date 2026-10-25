/*
 * This file is auto-generated.  DO NOT MODIFY.
 */
package cc.aaro.cosign;
/** The main process, as the signer tells it what changed (SignerClient). */
public interface ISignerClient extends android.os.IInterface
{
  /** Default implementation for ISignerClient. */
  public static class Default implements cc.aaro.cosign.ISignerClient
  {
    /** The accounts on this phone, by slot, and the one on screen. */
    @Override public void accounts(java.lang.String[] slots, java.lang.String active) throws android.os.RemoteException
    {
    }
    /** One account's state: a serialized Ui with every secret taken out (SignerService.forUi). */
    @Override public void state(java.lang.String slot, byte[] ui, java.lang.String label, boolean needsPaper) throws android.os.RemoteException
    {
    }
    @Override
    public android.os.IBinder asBinder() {
      return null;
    }
  }
  /** Local-side IPC implementation stub class. */
  public static abstract class Stub extends android.os.Binder implements cc.aaro.cosign.ISignerClient
  {
    /** Construct the stub at attach it to the interface. */
    public Stub()
    {
      this.attachInterface(this, DESCRIPTOR);
    }
    /**
     * Cast an IBinder object into an cc.aaro.cosign.ISignerClient interface,
     * generating a proxy if needed.
     */
    public static cc.aaro.cosign.ISignerClient asInterface(android.os.IBinder obj)
    {
      if ((obj==null)) {
        return null;
      }
      android.os.IInterface iin = obj.queryLocalInterface(DESCRIPTOR);
      if (((iin!=null)&&(iin instanceof cc.aaro.cosign.ISignerClient))) {
        return ((cc.aaro.cosign.ISignerClient)iin);
      }
      return new cc.aaro.cosign.ISignerClient.Stub.Proxy(obj);
    }
    @Override public android.os.IBinder asBinder()
    {
      return this;
    }
    @Override public boolean onTransact(int code, android.os.Parcel data, android.os.Parcel reply, int flags) throws android.os.RemoteException
    {
      java.lang.String descriptor = DESCRIPTOR;
      if (code >= android.os.IBinder.FIRST_CALL_TRANSACTION && code <= android.os.IBinder.LAST_CALL_TRANSACTION) {
        data.enforceInterface(descriptor);
      }
      switch (code)
      {
        case INTERFACE_TRANSACTION:
        {
          reply.writeString(descriptor);
          return true;
        }
      }
      switch (code)
      {
        case TRANSACTION_accounts:
        {
          java.lang.String[] _arg0;
          _arg0 = data.createStringArray();
          java.lang.String _arg1;
          _arg1 = data.readString();
          this.accounts(_arg0, _arg1);
          break;
        }
        case TRANSACTION_state:
        {
          java.lang.String _arg0;
          _arg0 = data.readString();
          byte[] _arg1;
          _arg1 = data.createByteArray();
          java.lang.String _arg2;
          _arg2 = data.readString();
          boolean _arg3;
          _arg3 = (0!=data.readInt());
          this.state(_arg0, _arg1, _arg2, _arg3);
          break;
        }
        default:
        {
          return super.onTransact(code, data, reply, flags);
        }
      }
      return true;
    }
    private static class Proxy implements cc.aaro.cosign.ISignerClient
    {
      private android.os.IBinder mRemote;
      Proxy(android.os.IBinder remote)
      {
        mRemote = remote;
      }
      @Override public android.os.IBinder asBinder()
      {
        return mRemote;
      }
      public java.lang.String getInterfaceDescriptor()
      {
        return DESCRIPTOR;
      }
      /** The accounts on this phone, by slot, and the one on screen. */
      @Override public void accounts(java.lang.String[] slots, java.lang.String active) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeStringArray(slots);
          _data.writeString(active);
          boolean _status = mRemote.transact(Stub.TRANSACTION_accounts, _data, null, android.os.IBinder.FLAG_ONEWAY);
        }
        finally {
          _data.recycle();
        }
      }
      /** One account's state: a serialized Ui with every secret taken out (SignerService.forUi). */
      @Override public void state(java.lang.String slot, byte[] ui, java.lang.String label, boolean needsPaper) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeString(slot);
          _data.writeByteArray(ui);
          _data.writeString(label);
          _data.writeInt(((needsPaper)?(1):(0)));
          boolean _status = mRemote.transact(Stub.TRANSACTION_state, _data, null, android.os.IBinder.FLAG_ONEWAY);
        }
        finally {
          _data.recycle();
        }
      }
    }
    static final int TRANSACTION_accounts = (android.os.IBinder.FIRST_CALL_TRANSACTION + 0);
    static final int TRANSACTION_state = (android.os.IBinder.FIRST_CALL_TRANSACTION + 1);
  }
  public static final java.lang.String DESCRIPTOR = "cc.aaro.cosign.ISignerClient";
  /** The accounts on this phone, by slot, and the one on screen. */
  public void accounts(java.lang.String[] slots, java.lang.String active) throws android.os.RemoteException;
  /** One account's state: a serialized Ui with every secret taken out (SignerService.forUi). */
  public void state(java.lang.String slot, byte[] ui, java.lang.String label, boolean needsPaper) throws android.os.RemoteException;
}
