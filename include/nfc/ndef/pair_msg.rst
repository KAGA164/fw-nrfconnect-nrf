.. _nfc_pair:

Pairing messages
################

Pairing messages contain :ref:`nfc_ch`.
They are used to establish an NFC connection and pair with other Bluetooth devices.

The library provides functions for encoding the following messages:

* Generic OOB message
* Handover Select message
* Handover Request message
* Handover Mediation message
* Handover Initiate message

This library is used in the :ref:`nfc_pairing` sample.

API documentation
*****************

.. _nfc_pair_msg:

| Header file: :file:`include/nfc/ndef/pair_msg.h`
| Source file: :file:`subsys/nfc/ndef/pair_msg.c`

.. doxygengroup:: nfc_ndef_pair_msg
   :project: nrf
   :members:
