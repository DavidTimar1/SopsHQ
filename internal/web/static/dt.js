// SopsHQ table enhancement: turn any <table class="dt"> into a DataTable with
// column sorting, a global search box, and paging. Header cells opt out of
// sorting with class "no-sort" and gain a Select2 dropdown column-filter with
// class "filter". Depends on jQuery + DataTables + Select2 (loaded before this).
(function () {
  "use strict";
  if (typeof window.jQuery === "undefined" || !window.jQuery.fn || !window.jQuery.fn.DataTable) {
    return;
  }
  var $ = window.jQuery;

  // initTable enhances one table element. It is exposed so dynamically built
  // tables (e.g. the reuse picker) can enhance themselves after insertion. opts
  // overrides the DataTable config; pass {paging:false} for tables whose rows must
  // all stay in the DOM (e.g. a picker with checkboxes that submit with a form).
  function initTable(tableEl, opts) {
    var $t = $(tableEl);
    if ($t.hasClass("dataTable") || $t.data("dt-done")) {
      return null; // already enhanced
    }
    $t.data("dt-done", true);

    var $headCells = $t.find("thead tr").first().find("th");
    var columnDefs = [];
    var filterCols = [];
    $headCells.each(function (i) {
      var $th = $(this);
      if ($th.hasClass("no-sort")) {
        columnDefs.push({ targets: i, orderable: false });
      }
      if ($th.hasClass("filter")) {
        filterCols.push(i);
      }
    });

    var config = {
      paging: true,
      pageLength: 25,
      lengthMenu: [[25, 50, 100, -1], [25, 50, 100, "All"]],
      order: [],
      autoWidth: false,
      columnDefs: columnDefs,
      // length + global filter on top, the table, then info + paging on the bottom.
      dom: '<"dt-top"lf>rt<"dt-bottom"ip>',
    };
    if ($t.hasClass("dt-nopage")) {
      config.paging = false;
    }
    if (opts) {
      for (var k in opts) { config[k] = opts[k]; }
    }
    if (config.paging === false) {
      config.dom = '<"dt-top"f>rt';
    }

    var dt = $t.DataTable(config);
    if (filterCols.length) {
      addColumnFilters($t, dt, $headCells, filterCols);
    }
    return dt;
  }

  // addColumnFilters appends a second header row of Select2 dropdowns, one per
  // column flagged "filter", each populated with that column's unique values and
  // wired to an exact-match column search.
  function addColumnFilters($t, dt, $headCells, filterCols) {
    var $row = $("<tr class='dt-filter-row'></tr>");
    $headCells.each(function (i) {
      var $cell = $("<th></th>");
      if (filterCols.indexOf(i) !== -1) {
        var $sel = $("<select><option value=''></option></select>");
        var seen = {};
        dt.column(i).data().each(function (d) {
          var text = $("<div>").html(d == null ? "" : String(d)).text().trim();
          if (text && !seen[text]) {
            seen[text] = true;
            $sel.append($("<option></option>").attr("value", text).text(text));
          }
        });
        $cell.append($sel);
      }
      $row.append($cell);
    });
    $t.find("thead").append($row);

    $row.find("select").each(function (idx) {
      var colIndex = filterCols[idx];
      var $sel = $(this);
      $sel.select2({ width: "100%", allowClear: true, placeholder: "All" });
      $sel.on("change", function () {
        var v = $sel.val() || "";
        var term = v ? "^" + $.fn.dataTable.util.escapeRegex(v) + "$" : "";
        dt.column(colIndex).search(term, true, false).draw();
      });
    });
  }

  $(function () {
    $("table.dt").each(function () { initTable(this); });
  });

  // Expose for dynamically inserted tables.
  window.SopsHQTable = { init: initTable };
})();
