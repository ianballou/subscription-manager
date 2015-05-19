#
# Copyright (C) 2015  Red Hat, Inc.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# the GNU General Public License v.2, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY expressed or implied, including the implied warranties of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
# Public License for more details.  You should have received a copy of the
# GNU General Public License along with this program; if not, write to the
# Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.  Any Red Hat trademarks that are incorporated in the
# source code or documentation are not subject to the GNU General Public
# License and may only be used or replicated with the express permission of
# Red Hat, Inc.
#

import logging

from pyanaconda.ui.gui.spokes import NormalSpoke
from pyanaconda.ui.common import FirstbootOnlySpokeMixIn
from pyanaconda.ui.gui.categories.system import SystemCategory
from pyanaconda.ui.gui import GUIObject

# need sys.path?

log = logging.getLogger(__name__)

#from gi.repository import Gtk
#from gi.repository from gi.repository import Gtk

from subscription_manager import ga
ga.GObject.threads_init()
from subscription_manager.gui import managergui
from subscription_manager.injectioninit import init_dep_injection
from subscription_manager import injection as inj
from subscription_manager.gui import registergui

__all__ = ["RHSMSpoke"]


class RHSMSpoke(FirstbootOnlySpokeMixIn, NormalSpoke):
    buildrObjects = ["RHSMSpokeWindow", "RHSMSpokeWindow-action_area1"]

    mainWidgetName = "RHSMSpokeWindow"

    uiFile = "rhsm_gui.ui"

    category = SystemCategory

    icon = "face-cool-symbolic"

    title = "Subscription Manager"

    def __init__(self, data, storage, payload, instclass):
        log.debug("I've been __init__()'ed")
        NormalSpoke.__init__(self, data, storage, payload, instclass)
        log.debug("data %s", repr(self.data))
        log.debug("storage %s", self.storage)
        log.debug("payload %s", self.payload)
        log.debug("instclass %s", self.instclass)
        self._done = False

    def initialize(self):
        log.debug("running self.initialize")
        NormalSpoke.initialize(self)
        self._done = False
        init_dep_injection()

        facts = inj.require(inj.FACTS)
        backend = managergui.Backend()
        log.debug("backend=%s", backend)

        self._registergui = registergui.RegisterScreen(backend, facts,
                                                       callbacks=[self.finished])
        self._action_area = self.builder.get_object("RHSMSpokeWindow-action_area1")
        self._register_box = self._registergui.dialog_vbox6

        # we have a ref to _register_box, but need to remove it from
        # the regustergui.window (a GtkDialog), and add it to the main
        # box in the action area of our initial-setup screen.
        self._registergui.window.remove(self._register_box)
        self._action_area.pack_end(self._register_box, True, True, 0)
        self._action_area.show()
        self._register_box.show_all()
        self._registergui.show()

    def finished(self):
        log.debug("finished callback")
        self._registergui.done()
        self._done = True

    # Update gui widgets to reflect state of self.data
    def refresh(self):
        #log.debug("refresh, self.data=%s", self.data)
        #log.debug("data.addons %s", self.data.addons)
        log.debug("data.addons.com_redhat_subscription_manager %s",
                  self.data.addons.com_redhat_subscription_manager)

        pass

    def apply(self):
        log.debug("apply")
        self.data.addons.com_redhat_subscription_manager.text = \
            "System is registered to Red Hat Subscription Management."

    def execute(self):
        log.debug("execute")

    @property
    def ready(self):
        log.debug(" READY")
        return True

    @property
    def completed(self):
        log.info(" COMPLETED")
        return self._done

    @property
    def mandatory(self):
        return False

    @property
    def status(self):
        log.debug("status prop")
        if self._done:
            return "System is registered to RHSM."
        else:
            return "System is not registered to RHSM."
