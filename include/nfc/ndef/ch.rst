.. _nfc_ch:

Connection Handover records
###########################

Connection Handover records and the corresponding :ref:`nfc_pair` are used to negotiate and activate an alternative communication carrier.
The negotiated communication carrier can then be used to perform certain activities between the two devices, such as Bluetooth pairing.

The Connection Handover library provides functions for creating and encoding the following Connection Handover records:

* Handover Request record
* Handover Select record
* Handover Mediation record
* Handover Initiate record
* Handover Carrier record
* Local records:

  * Alternative Carrier record
  * Collision Resolution record

The Connection Handover library is used in the :ref:`nfc_pairing` sample.

API documentation
*****************

| Header file: :file:`include/nfc/ndef/ch.h`
| Source file: :file:`subsys/nfc/ndef/ch.c`

.. _nfc_ndef_ch:

.. doxygengroup:: nfc_ndef_ch
   :project: nrf
   :members:
