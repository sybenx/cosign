/*
 * This file is auto-generated.  DO NOT MODIFY.
 */
package cc.aaro.cosign;
/**
 * The signer process, as the main process sees it (SignerService). Everything that goes in
 * is a slot, a word or a string; everything that comes out is a result or public state.
 * No call hands back a share, a secret key or a paper backup's code.
 */
public interface ISigner extends android.os.IInterface
{
  /** Default implementation for ISigner. */
  public static class Default implements cc.aaro.cosign.ISigner
  {
    /** Send [client] every account's state now, and again whenever it changes. */
    @Override public void listen(cc.aaro.cosign.ISignerClient client) throws android.os.RemoteException
    {
    }
    /** One of the UI's actions on an account (SignerService.act lists them all). */
    @Override public void act(java.lang.String slot, java.lang.String action, java.lang.String text, boolean flag) throws android.os.RemoteException
    {
    }
    /** "I already have an account": the nsec typed in, as characters, wiped once read. */
    @Override public void importKey(java.lang.String slot, char[] secret) throws android.os.RemoteException
    {
    }
    /** Sign the app's own event (a like, a follow, a reply, a mute): "event", or "approval" (what needs you), or "error". */
    @Override public android.os.Bundle signOwn(java.lang.String slot, java.lang.String event, boolean approved) throws android.os.RemoteException
    {
      return null;
    }
    /** The newest signed version of one of your lists ("3": follows), as JSON, or null. */
    @Override public java.lang.String latest(java.lang.String slot, java.lang.String key) throws android.os.RemoteException
    {
      return null;
    }
    /** A place for another account, shown: its slot. */
    @Override public java.lang.String add() throws android.os.RemoteException
    {
      return null;
    }
    @Override public void show(java.lang.String slot) throws android.os.RemoteException
    {
    }
    @Override public void forget(java.lang.String slot) throws android.os.RemoteException
    {
    }
    @Override
    public android.os.IBinder asBinder() {
      return null;
    }
  }
  /** Local-side IPC implementation stub class. */
  public static abstract class Stub extends android.os.Binder implements cc.aaro.cosign.ISigner
  {
    /** Construct the stub at attach it to the interface. */
    public Stub()
    {
      this.attachInterface(this, DESCRIPTOR);
    }
    /**
     * Cast an IBinder object into an cc.aaro.cosign.ISigner interface,
     * generating a proxy if needed.
     */
    public static cc.aaro.cosign.ISigner asInterface(android.os.IBinder obj)
    {
      if ((obj==null)) {
        return null;
      }
      android.os.IInterface iin = obj.queryLocalInterface(DESCRIPTOR);
      if (((iin!=null)&&(iin instanceof cc.aaro.cosign.ISigner))) {
        return ((cc.aaro.cosign.ISigner)iin);
      }
      return new cc.aaro.cosign.ISigner.Stub.Proxy(obj);
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
        case TRANSACTION_listen:
        {
          cc.aaro.cosign.ISignerClient _arg0;
          _arg0 = cc.aaro.cosign.ISignerClient.Stub.asInterface(data.readStrongBinder());
          this.listen(_arg0);
          reply.writeNoException();
          break;
        }
        case TRANSACTION_act:
        {
          java.lang.String _arg0;
          _arg0 = data.readString();
          java.lang.String _arg1;
          _arg1 = data.readString();
          java.lang.String _arg2;
          _arg2 = data.readString();
          boolean _arg3;
          _arg3 = (0!=data.readInt());
          this.act(_arg0, _arg1, _arg2, _arg3);
          break;
        }
        case TRANSACTION_importKey:
        {
          java.lang.String _arg0;
          _arg0 = data.readString();
          char[] _arg1;
          _arg1 = data.createCharArray();
          this.importKey(_arg0, _arg1);
          break;
        }
        case TRANSACTION_signOwn:
        {
          java.lang.String _arg0;
          _arg0 = data.readString();
          java.lang.String _arg1;
          _arg1 = data.readString();
          boolean _arg2;
          _arg2 = (0!=data.readInt());
          android.os.Bundle _result = this.signOwn(_arg0, _arg1, _arg2);
          reply.writeNoException();
          _Parcel.writeTypedObject(reply, _result, android.os.Parcelable.PARCELABLE_WRITE_RETURN_VALUE);
          break;
        }
        case TRANSACTION_latest:
        {
          java.lang.String _arg0;
          _arg0 = data.readString();
          java.lang.String _arg1;
          _arg1 = data.readString();
          java.lang.String _result = this.latest(_arg0, _arg1);
          reply.writeNoException();
          reply.writeString(_result);
          break;
        }
        case TRANSACTION_add:
        {
          java.lang.String _result = this.add();
          reply.writeNoException();
          reply.writeString(_result);
          break;
        }
        case TRANSACTION_show:
        {
          java.lang.String _arg0;
          _arg0 = data.readString();
          this.show(_arg0);
          break;
        }
        case TRANSACTION_forget:
        {
          java.lang.String _arg0;
          _arg0 = data.readString();
          this.forget(_arg0);
          break;
        }
        default:
        {
          return super.onTransact(code, data, reply, flags);
        }
      }
      return true;
    }
    private static class Proxy implements cc.aaro.cosign.ISigner
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
      /** Send [client] every account's state now, and again whenever it changes. */
      @Override public void listen(cc.aaro.cosign.ISignerClient client) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeStrongInterface(client);
          boolean _status = mRemote.transact(Stub.TRANSACTION_listen, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
      /** One of the UI's actions on an account (SignerService.act lists them all). */
      @Override public void act(java.lang.String slot, java.lang.String action, java.lang.String text, boolean flag) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeString(slot);
          _data.writeString(action);
          _data.writeString(text);
          _data.writeInt(((flag)?(1):(0)));
          boolean _status = mRemote.transact(Stub.TRANSACTION_act, _data, null, android.os.IBinder.FLAG_ONEWAY);
        }
        finally {
          _data.recycle();
        }
      }
      /** "I already have an account": the nsec typed in, as characters, wiped once read. */
      @Override public void importKey(java.lang.String slot, char[] secret) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeString(slot);
          _data.writeCharArray(secret);
          boolean _status = mRemote.transact(Stub.TRANSACTION_importKey, _data, null, android.os.IBinder.FLAG_ONEWAY);
        }
        finally {
          _data.recycle();
        }
      }
      /** Sign the app's own event (a like, a follow, a reply, a mute): "event", or "approval" (what needs you), or "error". */
      @Override public android.os.Bundle signOwn(java.lang.String slot, java.lang.String event, boolean approved) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        android.os.Bundle _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeString(slot);
          _data.writeString(event);
          _data.writeInt(((approved)?(1):(0)));
          boolean _status = mRemote.transact(Stub.TRANSACTION_signOwn, _data, _reply, 0);
          _reply.readException();
          _result = _Parcel.readTypedObject(_reply, android.os.Bundle.CREATOR);
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      /** The newest signed version of one of your lists ("3": follows), as JSON, or null. */
      @Override public java.lang.String latest(java.lang.String slot, java.lang.String key) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        java.lang.String _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeString(slot);
          _data.writeString(key);
          boolean _status = mRemote.transact(Stub.TRANSACTION_latest, _data, _reply, 0);
          _reply.readException();
          _result = _reply.readString();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      /** A place for another account, shown: its slot. */
      @Override public java.lang.String add() throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        java.lang.String _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          boolean _status = mRemote.transact(Stub.TRANSACTION_add, _data, _reply, 0);
          _reply.readException();
          _result = _reply.readString();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public void show(java.lang.String slot) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeString(slot);
          boolean _status = mRemote.transact(Stub.TRANSACTION_show, _data, null, android.os.IBinder.FLAG_ONEWAY);
        }
        finally {
          _data.recycle();
        }
      }
      @Override public void forget(java.lang.String slot) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeString(slot);
          boolean _status = mRemote.transact(Stub.TRANSACTION_forget, _data, null, android.os.IBinder.FLAG_ONEWAY);
        }
        finally {
          _data.recycle();
        }
      }
    }
    static final int TRANSACTION_listen = (android.os.IBinder.FIRST_CALL_TRANSACTION + 0);
    static final int TRANSACTION_act = (android.os.IBinder.FIRST_CALL_TRANSACTION + 1);
    static final int TRANSACTION_importKey = (android.os.IBinder.FIRST_CALL_TRANSACTION + 2);
    static final int TRANSACTION_signOwn = (android.os.IBinder.FIRST_CALL_TRANSACTION + 3);
    static final int TRANSACTION_latest = (android.os.IBinder.FIRST_CALL_TRANSACTION + 4);
    static final int TRANSACTION_add = (android.os.IBinder.FIRST_CALL_TRANSACTION + 5);
    static final int TRANSACTION_show = (android.os.IBinder.FIRST_CALL_TRANSACTION + 6);
    static final int TRANSACTION_forget = (android.os.IBinder.FIRST_CALL_TRANSACTION + 7);
  }
  public static final java.lang.String DESCRIPTOR = "cc.aaro.cosign.ISigner";
  /** Send [client] every account's state now, and again whenever it changes. */
  public void listen(cc.aaro.cosign.ISignerClient client) throws android.os.RemoteException;
  /** One of the UI's actions on an account (SignerService.act lists them all). */
  public void act(java.lang.String slot, java.lang.String action, java.lang.String text, boolean flag) throws android.os.RemoteException;
  /** "I already have an account": the nsec typed in, as characters, wiped once read. */
  public void importKey(java.lang.String slot, char[] secret) throws android.os.RemoteException;
  /** Sign the app's own event (a like, a follow, a reply, a mute): "event", or "approval" (what needs you), or "error". */
  public android.os.Bundle signOwn(java.lang.String slot, java.lang.String event, boolean approved) throws android.os.RemoteException;
  /** The newest signed version of one of your lists ("3": follows), as JSON, or null. */
  public java.lang.String latest(java.lang.String slot, java.lang.String key) throws android.os.RemoteException;
  /** A place for another account, shown: its slot. */
  public java.lang.String add() throws android.os.RemoteException;
  public void show(java.lang.String slot) throws android.os.RemoteException;
  public void forget(java.lang.String slot) throws android.os.RemoteException;
  /** @hide */
  static class _Parcel {
    static private <T> T readTypedObject(
        android.os.Parcel parcel,
        android.os.Parcelable.Creator<T> c) {
      if (parcel.readInt() != 0) {
          return c.createFromParcel(parcel);
      } else {
          return null;
      }
    }
    static private <T extends android.os.Parcelable> void writeTypedObject(
        android.os.Parcel parcel, T value, int parcelableFlags) {
      if (value != null) {
        parcel.writeInt(1);
        value.writeToParcel(parcel, parcelableFlags);
      } else {
        parcel.writeInt(0);
      }
    }
  }
}
