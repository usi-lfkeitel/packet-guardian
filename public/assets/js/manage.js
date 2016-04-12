j.OnReady(function() {
    j.Click('[name=logout-btn]', function() {
        location.href = "/logout";
        return;
    });
    j.Click('[name=add-device-btn]', function() {
        location.href = "/register?manual=1";
        return;
    });
    j.Click('[name=del-selected-btn]', function() {
        var checked = j.$('.device-select:checked', true);
        var username = j.$('[name=username]').value;
        var devicesToRemove = [];
        for (var i = 0; i < checked.length; i++) {
            devicesToRemove.push(checked[i].value);
        }
        j.Post('/devices/delete', {"devices": devicesToRemove, "username": username}, function(resp) {
            resp = JSON.parse(resp);
            if (resp.Code === 0) {
                location.reload();
                return;
            }
            c.FlashMessage("Error deleteing devices");
        });
    });
    j.Click('[name=del-all-btn]', function() {
        var username = j.$('[name=username]').value;
        j.Post('/devices/delete', {"username": username}, function(resp) {
            resp = JSON.parse(resp);
            if (resp.Code === 0) {
                location.reload();
                return;
            }
            c.FlashMessage("Error deleteing devices");
        });
    });
});
