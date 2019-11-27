.. _nfc_tnep_poller:

NFC: TNEP Poller
################

The NFC TNEP Poller Tag samples demonstrates how to use the :ref:`tnep_poller_readme` library to exchange data using NFC TNEP Protocol on the NFC Poller Device.

Overview
********

The sample shows how to use NFC TNEP Protocol on the NFC Poller Device. Sample can
interact with the NFC Type 4 Tag. On the beginning sample reads the NFC Type 4 Tag and look for the TNEP Initial Message.
After that the first service found is selected and Poller attempts to exchage data. Next the service is deselected.

Requirements
************
One of the following boards:

  * nRF52 Development Kit board (PCA10040)
  * nRF52840 Development Kit board (PCA10056)

* NFC Reader ST25R3911B Nucleo expansion board (X-NUCLEO-NFC05A1)
* NFC Type 4 Tag TNEP Device

Building and running
********************
.. |sample path| replace:: :file:`samples/nfc/tnep_poller`

.. include:: /includes/build_and_run.txt

Testing
=======
After programming the sample to your board, you can test it with an NFC-A Tag Device
which support NFC TNEP Protocols.

1. |connect_terminal|
#. Reset the board.
#. Put the NFC Tag Device anntena in NFC Poller range.
#. The NFC Poller Device select the first service and provide simple
   data exchange with it. After that service will be deselected.
#. Observe the output in the terminal.

This sample uses the following |NCS| drivers:

* :ref:`st25r3911b_nfc_readme`

This sample uses the following |NCS| libraries:

* :ref:`tnep_poller_readme`
* :ref:`nfc_ndef_parser_readme`
* :ref:`nfc_t4t_apdu_readme`
* :ref:`nfc_t4t_isodep_readme`
* :ref:`nfc_t4t_hl_procedure_readme`

In addition, it uses the following Zephyr libraries:

* ``include/zephyr/types.h``
* ``include/misc/printk.h``
* ``include/sys/byteorder.h``
* ``include/zephyr.h``
