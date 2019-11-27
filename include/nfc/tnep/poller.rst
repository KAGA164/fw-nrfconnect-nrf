.. _tnep_poller_readme:

Tag NDEF Exchange Protocol for NFC Poller Device
################################################

TNEP (The Tag NDEF Exchange Protocol) is an application-level protocol for sending or
retrieving application data units, in the form of NFC Data Exchange Format (NDEF) messages,
between one Reader/Writer and an NFC Tag Device. It operates between Type X Tag and NDEF application layer.

After read of the NDEF message from the NFC Type X Tag Device, this library can
look for TNEP Initial NDEF message which contains the Service Parameters Records
using the :cpp:func:`nfc_tnep_poller_svc_search`. If the NDEF Message has valid Service Parameters Records, the service can be selected using :cpp:func:`nfc_tnep_poller_svc_select` after finish all operation on this service, it should be deselected by selecting another service or using :cpp:func:`nfc_tnep_poller_svc_deselect`.

Single Response Communication Mode
**********************************

The Poller Device using the Single Response Communication Mode to exchange the
NDEF Message according to NFC Forum TNEP specification chapter 5. Exchange data is
possible only when service is selected. Data is exchange in NDEF Read and NDEF Write operation. To exchange data use the :cpp:func:`nfc_tnep_poller_svc_update` or
:cpp:func:`nfc_tnep_poller_on_ndef_read`.

Note that this operations are asynchronous.

When the NFC Poller device finish the NDEF Write or Read procedure the application should inform the library about is calling respectively :cpp:func:`nfc_tnep_poller_on_ndef_read` or :cpp:func:`nfc_tnep_poller_on_ndef_update`.

API documentation
*****************

| Header file: :file:`include/tnep/poller.h`
| Source file: :file:`subsys/tnep/poller.c`

.. doxygengroup:: nfc_tnep_poller
   :project: nrf
   :members:
