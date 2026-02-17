document.addEventListener("DOMContentLoaded", function () {
  const table = document.getElementById("complaintsTable");
  if (table) {
    new DataTable(table, {
      pageLength: 10,
      order: [[5, "desc"]]
    });
  }
});
