(function () {
  "use strict";

  function updateCmdbField(row, clearSelection) {
    const addressType = row.querySelector('select[name$="-address_type"]');
    const cmdbField = row.querySelector(".field-cmdb_mapping");

    if (!addressType || !cmdbField) {
      return;
    }

    const isIp = addressType.value === "ip";
    cmdbField.hidden = !isIp;
    cmdbField.setAttribute("aria-hidden", String(!isIp));

    if (!isIp && clearSelection) {
      const selection = cmdbField.querySelector("select");
      if (selection && selection.value) {
        selection.value = "";
        selection.dispatchEvent(new Event("change", { bubbles: true }));
      }
    }
  }

  function updateAllRows(container) {
    container.querySelectorAll(".inline-related").forEach(function (row) {
      updateCmdbField(row, false);
    });
  }

  function fillAddressFromCmdb(row, selection) {
    if (!selection.value) {
      return;
    }

    const addressType = row.querySelector('select[name$="-address_type"]');
    const address = row.querySelector('input[name$="-address"]');
    const selectedOption = selection.options[selection.selectedIndex];
    if (!addressType || addressType.value !== "ip" || !address || !selectedOption) {
      return;
    }

    const assetAddress = selectedOption.textContent.trim().split(" — ", 1)[0];
    if (assetAddress) {
      address.value = assetAddress;
      address.dispatchEvent(new Event("input", { bubbles: true }));
      address.dispatchEvent(new Event("change", { bubbles: true }));
    }
  }

  document.addEventListener("change", function (event) {
    if (event.target.matches('select[name$="-cmdb_mapping"]')) {
      const row = event.target.closest(".inline-related");
      if (row) {
        fillAddressFromCmdb(row, event.target);
      }
      return;
    }

    if (!event.target.matches('select[name$="-address_type"]')) {
      return;
    }

    const row = event.target.closest(".inline-related");
    if (row) {
      updateCmdbField(row, true);
    }
  });

  document.addEventListener("formset:added", function (event) {
    updateCmdbField(event.target, false);
    updateAllRows(event.target);
  });

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".inline-group").forEach(updateAllRows);
  });
})();
