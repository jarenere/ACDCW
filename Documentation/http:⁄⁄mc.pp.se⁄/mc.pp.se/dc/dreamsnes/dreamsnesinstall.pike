#!/usr/bin/env pike

// Invariants

constant root_resource = "http://mc.pp.se/dc/dreamsnes/MANIFEST";

constant installer_version = 1.6;

constant tmp_dir = "./";

constant pubkey_data = MIME.decode_base64(#"
mQGiBDxoV3IRBAChUosVpfNWIqhh7g/VNZPv16x3+0WOIyBpLiDSNt1NnEyIP5MDveTwLO0a2SIL
5ScC97gXJENNWSwVH9QpL6xepT7w6tmkgZZLP6s6NeoyC2vFk5fGDaGnvAb4XoPCO+XUEItNTAVy
wqH7hZIXF4zTjZmUFz2CZYeTU/Ek/pkTVwCg8qYqy2hFVRMBOJFtqCpykiCYXR0D/iYxnMzSAotD
yFRVpg0sbHZDTgWd+mojy/5Uslxp32KMX+RMrFhAhoOQsjdmbewVgLsqKlJR1wE8vIukZQ0Poug1
AOn9Y52MLC4S0AvI/gZ67i95ulmxqzpHgUygtaDTOegGm2PzVcks+UIytskyboQs4bH79TYIxNGf
ubl3QseaA/9zk6TJR84cbdeZDeAx6jtakyIiQ2ASfyV08Vizxi7lozrbNI9JMzQ0gnuSoU+20aBw
r3dY4H/5XxNm7CtNC1f0YGOpZev1tplEg3aTPxPPTAyDFXz6zAV1NPyFjG1lQuT2r3FTIdyPpKWF
vuDgXDaQqLvd85EnAKh1R3k5TBW26LQORHJlYW1TTkVTIFRlYW2IVwQTEQIAFwUCPGhXcgULBwoD
BAMVAwIDFgIBAheAAAoJEHVpXtHTanZIQBsAn1FZlukRp6sCA21t0He3YpvakVs4AJ97YVTKFO4+
0u6vsgawb8ANXC47iA==
");


constant cdrecord_homepage = "http://www.fokus.gmd.de/research/cc/"
"glone/employees/joerg.schilling/private/cdrecord.html";


// PGP stuff...

mapping decode_PGP_public_key(string s)
{
  mapping r = ([]);
  string key;
  int l;
  if(s[0]>=4)
    sscanf(s, "%1c%4c%1c%2c%s", r->version, r->tstamp,
	   r->type, l, key);
  else
    sscanf(s, "%1c%4c%2c%1c%2c%s", r->version, r->tstamp, r->validity,
	   r->type, l, key);

  if(r->type == 1) {
    Gmp.mpz n, e;

    l = (l+7)>>3;
    n = Gmp.mpz(key[..l-1],256);
    sscanf(key[l..], "%2c%s", l, key);
    l = (l+7)>>3;
    e = Gmp.mpz(key[..l-1],256);
    r->key = Crypto.rsa()->set_public_key(n, e);
  } else if(r->type == 17) {
    Gmp.mpz p, q, g, y;

    l = (l+7)>>3;
    p = Gmp.mpz(key[..l-1],256);
    sscanf(key[l..], "%2c%s", l, key);
    l = (l+7)>>3;
    q = Gmp.mpz(key[..l-1],256);
    sscanf(key[l..], "%2c%s", l, key);
    l = (l+7)>>3;
    g = Gmp.mpz(key[..l-1],256);
    sscanf(key[l..], "%2c%s", l, key);
    l = (l+7)>>3;
    y = Gmp.mpz(key[..l-1],256);
    r->key = Crypto.dsa()->set_public_key(p, q, g, y);
  }
  return r;
}

mapping decode_PGP_signature(string s)
{
  mapping r = ([]);
  int l5, l;
  string dig;
  sscanf(s, "%1c%1c%1c%4c%8s%1c%1c%2c%2c%s", r->version, l5, r->classification,
	 r->tstamp, r->key_id, r->type, r->digest_algorithm,
	 r->md_csum, l, dig);
  if(r->type == 1) {
    l = (l+7)>>3;
    r->digest = Gmp.mpz(dig[..l-1],256);
  } else if(r->type == 17) {
    l = (l+7)>>3;
    r->digest_r = Gmp.mpz(dig[..l-1],256);
    sscanf(dig[l..], "%2c%s", l, dig);
    l = (l+7)>>3;
    r->digest_s = Gmp.mpz(dig[..l-1],256);
  }
  return r;
}

mapping(string:string|mapping) decode_PGP(string s)
{
  constant pgp_id = ([
    0b100001:"public_key_encrypted",
    0b100010:"signature",
    0b100101:"secret_key",
    0b100110:"public_key",
    0b101000:"compressed_data",
    0b101001:"conventional_key_encrypted",
    0b101011:"literal_data",
    0b101100:"keyring_trust",
    0b101101:"user_id",
  ]);
  mapping pgp_decoder = ([
    "public_key":decode_PGP_public_key,
    "signature":decode_PGP_signature,
  ]);
  mapping(string:string|mapping) r = ([]);
  int i = 0;
  while(i<strlen(s)) {
    int h = s[i++];
    int data_l = 0;
    switch(h&3) {
     case 0:
       sscanf(s[i..i], "%1c", data_l);
       i++;
       break;
     case 1:
       sscanf(s[i..i+1], "%2c", data_l);
       i+=2;
       break;
     case 2:
       sscanf(s[i..i+3], "%4c", data_l);
       i+=4;
       break;       
     case 3:
       data_l = strlen(s)-i;
       break;
    }
    if(i+data_l > strlen(s))
      throw(({"Bad PGP data\n", backtrace()}));
    h>>=2;
    if(pgp_id[h])
      r[pgp_id[h]] = (pgp_decoder[pgp_id[h]] || `+)(s[i..i+data_l-1]);
    i += data_l;
  }
  return r;
}

int PGP_verify(Crypto.md5 hash, mapping sig, mapping key)
{
  if(!objectp(hash) || !mappingp(sig) || !mappingp(key) || !key->key)
    return 0;

  if(sig->type != key->type)
    return 0;

  string digest = hash->update(sprintf("%c%4c", sig->classification,
				       sig->tstamp))->digest();
  int csum;
  if(1 != sscanf(digest, "%2c", csum) || csum != sig->md_csum)
    return 0;
    
  if(key->type == 1 && sig->digest_algorithm == 1)

    return key->key->raw_verify("0 0\14\6\10*\x86H\x86\xf7\15\2\5\5\0\4\20"+
				digest, sig->digest);

  else if(key->type == 17)

    return key->key->raw_verify(Gmp.mpz(digest,256),
				sig->digest_r, sig->digest_s);

  else
    return 0;
}


// Pipes

array(Stdio.File) make_pipes()
{
  Stdio.File w_pipe = Stdio.File();
  Stdio.File r_pipe = w_pipe->pipe();
  return ({w_pipe, r_pipe});
}

// GUI

#define GUI_SLEEP 0.005

class GUI
{
  constant INFO = 1;
  constant WARNING = 2;
  constant ERROR = 3;
  constant FATAL = 4;

  void status_popup(string msg);
  void status_popdown();
  void display_message(int severity, string msg);
  void display_checklist(array(string) names);
  void checklist_result(int index, int|string result);
  void remove_checklist();
  void display_destinations(array(string) names);
  void display_applications(array(string) names);
  void remove_destinations();
  void remove_applications();
  array(string|int|array) finalize_selections();
  void progress_popup(string msg);
  void progress_update(int curr, int max);
  void progress_popdown();
  string query_filename(string prompt);
  Stdio.File get_output_pipe();
  void cleanup()
  {
    status_popdown();
    progress_popdown();
    remove_destinations();
    remove_applications();
    remove_checklist();
  }
  static void create()
  {
    atexit(cleanup);
  }
}

class GUIProxy
{
  inherit GUI;

  static program gui_program;
  static Thread.Thread gui_thread;
  static Thread.Fifo fifo = Thread.Fifo();
  static Thread.Fifo return_fifo = Thread.Fifo();
  static GUI real_gui;

  static void slave_thread(array args)
  {
    real_gui = gui_program(@args);
    for(;;) {
      if(fifo->size())
	foreach(fifo->read_array(), [function f, array args]) {
	  mixed r = f(@args);
	  return_fifo->write(r);
	  if(f == real_gui->cleanup)
	    return;
	}
      else if(real_gui->update && real_gui->update())
	;
      else
	sleep(GUI_SLEEP);
    }
  }

  mixed `->(string idx)
  {
    if(idx == "cleanup")
      return cleanup;

    mixed f = real_gui[idx];
    return functionp(f) && lambda(mixed ... args) {
			     fifo->write(({ f, args }));
			     return return_fifo->read();
			   };
  }

  void cleanup()
  {
    fifo->write(({real_gui->cleanup, ({})}));
    return_fifo->read();
    gui_thread->wait();
  }

  static void create(program p, mixed ... args)
  {
    gui_program = p;
    gui_thread = thread_create(slave_thread, args);
    while(!real_gui)
      sleep(0.1);
  }

}

class GtkGUI
{
  inherit GUI;

  static class Gtk_status_popup
  {
    inherit GTK.Window;

    static int popupped = 0;
    static GTK.Label label;

    void popup(string msg)
    {
      label->set_text(msg);
      if(!popupped) {
	mapping(string:int) root_geom = GTK.root_window()->get_geometry();
	::popup((root_geom->width-300)/2, (root_geom->height-50)/2);
	popupped = 1;
      }
    }

    void popdown()
    {
      if(popupped) {
	::hide();
	popupped = 0;
      }
    }

    static void create()
    {
      ::create(GTK.WINDOW_POPUP);
      add(GTK.Frame()->add((label = GTK.Label(""))->show())
	  ->set_shadow_type(GTK.SHADOW_OUT)->show());
      set_usize(300, 50);
    }
  }
  static Gtk_status_popup s_popup;

  void status_popup(string msg)
  {
    if(!s_popup)
      s_popup = Gtk_status_popup();
    s_popup->popup(msg);
  }

  void status_popdown()
  {
    if(s_popup)
      s_popup->popdown();
  }

  static class Gtk_toplevel
  {
    inherit GTK.Window;

    static class Gtk_checklist
    {
      inherit GTK.Frame;
      static GTK.Clist clist;

      static void create()
      {
	::create("Task list");
	clist = GTK.Clist(2);
	clist->show();
	add(clist);
	clist->set_column_auto_resize(0,1);
      }
      
      void set_names(array(string) names)
      {
	clist->clear();
	foreach(names, string name)
	  clist->append(({name+".....", ""}));
      }
      
      void set_result(int index, int|string result)
      {
	clist->set_text(index, 1, stringp(result)? result :
			(result? "Ok":"FAILED"));
      }
    }
    Gtk_checklist c_list;

    static class Gtk_outpipe_window
    {
      inherit GTK.Frame;
      static GTK.Text text;
      
      static Stdio.File w_pipe, r_pipe;
      
      Stdio.File get_pipe() { return w_pipe; }
      
      void update()
      {
	string s = r_pipe->read(100,1);
	if(s && sizeof(s))
	  text->insert(s);
      }
      
      static void create()
      {
	::create("Messages");
	add(text = GTK.Text(0,0)->show());
	[w_pipe, r_pipe] = make_pipes();
	r_pipe->set_nonblocking();
      }
    }
    Gtk_outpipe_window op_window;

    static class Gtk_destination_selector
    {
      inherit GTK.Frame;
      static GTK.Combo combo;
      static GTK.CheckButton cb;
      static string imgsel;
      static string selected;

      array(string|int) get_selected()
      {
	return ({ selected, cb->get_active() });
      }

      void set_options(array(string) list)
      {
	imgsel = list[-1];
	combo->set_popdown_strings(list);
	selected = list[0];
      }

      static void create()
      {
	::create("Burner selection");
	GTK.Hbox box = GTK.Hbox(0,10);
	box->pack_start(combo = GTK.Combo()->show(), 1, 1, 0);
	box->pack_end(cb = GTK.CheckButton("Direct burn")->show(), 0, 0, 0);
	combo->set_value_in_list(1, 0);
	Array.filter(combo->children(), lambda(object w) {
					  return w->get_name() == "GtkEntry";
					})->
	  signal_connect("insert-text", lambda(mixed id, GTK.Widget w,
					       string data, int l) {
					  selected = data;
					  data = data[..l-1];
					  cb->set_sensitive(data != imgsel);
					});
	add(box->show());
      }
    }
    Gtk_destination_selector dest_sel;

    static class Gtk_application_list
    {
      inherit GTK.Frame;
      static GTK.Clist clist;
      static string selected;

      string get_selected()
      {
	return selected;
      }

      void set_options(array(string) list)
      {
	clist->clear();
	foreach(list, string s)
	  clist->append(({s}));
      }

      static void create()
      {
	::create("Application selector");
	clist = GTK.Clist(1);
	clist->show();
	add(clist);
	clist->signal_connect("select-row",
			      lambda(mixed id, GTK.Widget w, int row) {
				selected = (string)clist->get_text(row, 0);
				launch_button->set_sensitive(1);
			      });
	clist->signal_connect("unselect-row",
			      lambda(mixed id, GTK.Widget w, int row) {
				launch_button->set_sensitive(0);
				selected = 0;
			      });
      }
    }
    Gtk_application_list app_list;

    
    static class Gtk_rom_list
    {
      inherit GTK.Vbox;
      static GTK.Clist clist;
      static GTK.Vscrollbar scroll;
      static GTK.Button add_button, rename_button, remove_button;
      static GTK.FileSelection filesel;
      static GTK.Dialog rename_popup, dirconfirm_popup;
      static GTK.Entry rename_entry;
      static GTK.Label dirconfirm_label;
      static multiset(int) selection = (<>);
      static array(ROMFile) roms = ({});
      static int rename_row;
      static string dir_to_add;

      array(ROMFile) get_roms() { return roms; }

      static void add_file(string fn)
      {
	Stdio.Stat st = file_stat(fn);
	if(!st)
	  return;
	if(st->isdir) {
	  dir_to_add = fn;
	  dirconfirm_label->set_text("Do you want to add all files in\n"+
				      fn+"\nand below into the list?");
	  dirconfirm_popup->show();
	} else {
	  roms += ({ ROMFile(fn) });
	  clist->append(({roms[-1]->get_name(), fn}));
	}
      }

      static void add_dir(string dn)
      {
	foreach(get_dir(dn), string f) {
	  string n = combine_path(dn, f);
	  Stdio.Stat st = file_stat(n);
	  if(st && st->isdir)
	    add_dir(n);
	  else if(!(st[1]&0x7fff) || !((st[1]+0x7e00)&0x7fff))
	    add_file(n);
	}
      }

      static void do_filesel(int ok)
      {
	if(ok)
	  add_file(filesel->get_filename());
	filesel->hide();
	add_button->set_sensitive(1);
      }

      static void do_rename()
      {
	if(sizeof(selection) != 1)
	  return;
	int r = indices(selection)[0];
	if(r<0 || r>=sizeof(roms))
	  return;
	rename_row = r;
	rename_entry->set_text(roms[r]->get_name());
	rename_popup->show();
      }

      static void do_remove()
      {
	foreach(reverse(sort(indices(selection))), int r) {
	  roms = roms[..r-1]+roms[r+1..];
	  clist->remove(r);
	}
      }

      static void create()
      {
	::create(0,5);
	GTK.Hbox hbox = GTK.Hbox(0,0);
	GTK.Adjustment adj = GTK.Adjustment();
	hbox->pack_end((scroll = GTK.Vscrollbar(adj))->show(), 0, 0, 0);
	hbox->pack_start((clist = GTK.Clist(2))->set_vadjustment(adj)->show(),
			 1, 1, 0);
	pack_start(hbox->show(), 1, 1, 0);
	clist->set_column_title(0, "Name")->set_column_title(1, "Location")->
	  set_column_auto_resize(0, 1)->set_column_auto_resize(1, 1)->
	  column_title_passive(0)->column_title_passive(1)->
	  column_titles_show();
	clist->set_selection_mode(GTK.SELECTION_EXTENDED);
	GTK.HbuttonBox box = GTK.HbuttonBox();
	box->add(add_button = GTK.Button("Add")->show());
	box->add(rename_button = GTK.Button("Rename")->show());
	box->add(remove_button = GTK.Button("Remove")->show());
	pack_end(box->show(), 0, 0, 0);
	rename_button->set_sensitive(0);
	remove_button->set_sensitive(0);
	clist->signal_connect("select-row",
			      lambda(mixed id, GTK.Widget w, int row) {
				selection[row] = 1;
				if(sizeof(selection)==1) {
				  rename_button->set_sensitive(1);
				  remove_button->set_sensitive(1);
				} else
				  rename_button->set_sensitive(0);
			      });
	clist->signal_connect("unselect-row",
			      lambda(mixed id, GTK.Widget w, int row) {
				selection[row] = 0;
				if(!sizeof(selection)) {
				  rename_button->set_sensitive(0);
				  remove_button->set_sensitive(0);
				} else if(sizeof(selection)==1)
				  rename_button->set_sensitive(1);
			      });
	filesel = GTK.FileSelection("Select ROM file or directory");
	filesel->ok_button()->signal_connect("clicked", lambda() {
							  do_filesel(1);
							});
	filesel->cancel_button()->signal_connect("clicked", lambda() {
							      do_filesel(0);
							    });
	(dirconfirm_popup = GTK.Dialog())->set_modal(1);
	dirconfirm_popup->vbox()->add(dirconfirm_label =
				      GTK.Label("")->show());
	GTK.Button dircon_ok, dircon_cancel;
	dirconfirm_popup->action_area()->add(dircon_ok =
					     GTK.Button("Ok")->show());
	dirconfirm_popup->action_area()->add(dircon_cancel = 
					     GTK.Button("Cancel")->show());
	dircon_ok->signal_connect("clicked", lambda() {
					       add_dir(dir_to_add);
					       dirconfirm_popup->hide();
					     });
	dircon_cancel->signal_connect("clicked", dirconfirm_popup->hide);
	add_button->signal_connect("clicked", lambda() {
						add_button->set_sensitive(0);
						filesel->show();
					      });
	(rename_popup = GTK.Dialog())->set_modal(1);
	rename_popup->vbox()->add(rename_entry = GTK.Entry()->show());
	GTK.Button rename_ok, rename_cancel;
	rename_popup->action_area()->add(rename_ok = GTK.Button("Ok")->show());
	rename_popup->action_area()->add(rename_cancel = 
					 GTK.Button("Cancel")->show());
	rename_ok->signal_connect("clicked",
				  lambda() {
				    string name=rename_entry->get_text();
				    roms[rename_row]->set_name(name);
				    clist->set_text(rename_row, 0,
						    roms[rename_row]->
						    get_name());
				    rename_popup->hide();
				  });
	rename_cancel->signal_connect("clicked", rename_popup->hide);
	rename_button->signal_connect("clicked", do_rename);
	remove_button->signal_connect("clicked", do_remove);
      }
    }
    Gtk_rom_list rom_list;

    static multiset(GTK.Widget) shown = (<>);
    static GTK.Notebook notebook;
    static GTK.Button launch_button;
    static int launch_clicked;

    Gtk_toplevel show(GTK.Widget w)
    {
      if(!shown[w]) {
	w->show();
	if(w == app_list)
	  notebook->set_page(0);
	if(!sizeof(shown))
	  ::show();
	shown[w] = 1;
      }
      return this_object();
    }

    Gtk_toplevel hide(GTK.Widget w)
    {
      if(shown[w]) {
	w->hide();
	shown[w] = 0;
	if(!sizeof(shown))
	  ::hide();
      }
      return this_object();
    }

    array(string|int|array) finalize_selections()
    {
      launch_clicked = 0;
      launch_button->show();
      while(!launch_clicked)
	if(!update())
	  sleep(GUI_SLEEP);
      launch_button->set_sensitive(0);
      set_sensitive(0);
      return ({ @dest_sel->get_selected(), app_list->get_selected(),
		rom_list->get_roms() });
    }

    static void create()
    {
      ::create(GTK.WINDOW_TOPLEVEL);
      signal_connect("destroy", exit);
      set_usize(500, 400);
      notebook = GTK.Notebook();
      GTK.Vbox box = GTK.Vbox(0,10);
      box->pack_start(dest_sel = Gtk_destination_selector(), 0, 0, 0);
      box->pack_end(app_list = Gtk_application_list(), 1, 1, 0);
      notebook->append_page(box->show(), GTK.Label("Basic setup")->show());
      notebook->append_page((rom_list = Gtk_rom_list())->show(),
			    GTK.Label("ROM list")->show());
      box = GTK.Vbox(0,5);
      box->pack_start(c_list = Gtk_checklist(), 1, 1, 0);
      box->pack_start(launch_button = GTK.Button("Start"), 0, 0, 0);
      box->pack_end(op_window = Gtk_outpipe_window(), 1, 1, 0);
      launch_button->set_sensitive(0);
      launch_button->signal_connect("clicked", lambda() {
						 launch_clicked++;
					       });
      notebook->append_page(box->show(), GTK.Label("Action")->show());
      notebook->set_page(2);
      add(notebook->show());
    }
  }

  static Gtk_toplevel toplevel;

  void display_checklist(array(string) names)
  {
    toplevel->c_list->set_names(names);
    toplevel->show(toplevel->c_list);
  }

  void checklist_result(int index, int result)
  {
    toplevel->c_list->set_result(index, result);
  }

  void remove_checklist()
  {
    toplevel->hide(toplevel->c_list);
  }

  Stdio.File get_output_pipe()
  {
    toplevel->show(toplevel->op_window);
    return toplevel->op_window->get_pipe();
  }

  void display_destinations(array(string) names)
  {
    toplevel->dest_sel->set_options(names);
    toplevel->show(toplevel->dest_sel);
  }

  void remove_destinations()
  {
    toplevel->hide(toplevel->dest_sel);
  }

  void display_applications(array(string) names)
  {
    toplevel->app_list->set_options(names);
    toplevel->show(toplevel->app_list);
  }

  void remove_applications()
  {
    toplevel->hide(toplevel->app_list);
  }

  void display_message(int severity, string msg)
  {
    GTK.Dialog d = GTK.Alert(msg, ([
      INFO:"Info",
      WARNING:"Warning",
      ERROR:"Error",
      FATAL:"Fatal"
    ])[severity])->show();
    while(d)
      if(!update())
	sleep(GUI_SLEEP);
  }

  array(string|int|array) finalize_selections()
  {
    return toplevel->finalize_selections();
  }

  class Gtk_progress_indicator
  {
    inherit GTK.Window;

    static int popupped = 0;
    static GTK.Label label;
    static GTK.ProgressBar bar;

    void popup(string msg)
    {
      label->set_text(msg);
      if(!popupped) {
	mapping(string:int) root_geom = GTK.root_window()->get_geometry();
	::popup((root_geom->width-300)/2, (root_geom->height-50)/2);
	popupped = 1;
      }
    }

    void popdown()
    {
      if(popupped) {
	::hide();
	popupped = 0;
      }
    }

    void update_progress(int curr, int max)
    {
      if(curr <= max) {
	if(max > 32000) {
	  curr /= 100;
	  max /= 100;
	} 
	bar->configure((float)curr, 0.0, (float)max);
      }
    }

    static void create()
    {
      ::create(GTK.WINDOW_POPUP);
      add(GTK.Frame()->
	  add(GTK.Vbox(0,0)->
	      add((label = GTK.Label(""))->show())
	      ->add((bar = GTK.ProgressBar())->set_show_text(1)->show())
	      ->show())     
	  ->set_shadow_type(GTK.SHADOW_OUT)->show());
      set_usize(300, 50);
    }
  }

  static Gtk_progress_indicator progress;

  void progress_popup(string msg)
  {
    if(!progress)
      progress = Gtk_progress_indicator();
    progress->popup(msg);
  }

  void progress_update(int curr, int max)
  {
    if(progress)
      progress->update_progress(curr, max);
  }

  void progress_popdown()
  {
    if(progress)
      progress->popdown();
  }

  string query_filename(string prompt)
  {
    string res=0;
    int done=0;
    GTK.FileSelection filesel = GTK.FileSelection(prompt);
    filesel->ok_button()->signal_connect("clicked", lambda() {
						      res = filesel->
							get_filename();
						      done++;
						    });
    filesel->cancel_button()->signal_connect("clicked", lambda() {
							  done++;
							});
    filesel->show();
    while(!done)
      if(!update())
	sleep(GUI_SLEEP);
    filesel->hide();
    return res;
  }

  void cleanup()
  {
    ::cleanup();
  }

  int update()
  {
    toplevel->op_window->update();
    GTK.main_iteration_do(0);
    return 0;
  }

  static void create(array(string) argv)
  {
    catch { GTK.setup_gtk(argv); };
    toplevel = Gtk_toplevel();
    ::create();
  }
}


GUI gui;

// CdRecord interface

mapping(string:string) command_path = ([]);

array(array(string)) g_destination_locations;
array(string) g_mkisofsargs;
string g_ipbin_path;
int g_mkisofs_needs_graft_points = 0;

int do_command(array(string) argv, Stdio.File|void in, Stdio.File|void out,
	       Stdio.File|void err, function(:void)|void callback)
{
  Stdio.File outpipe = gui->get_output_pipe();
  Process.Process p = Process.Process(argv,
				      (["stdout":out||outpipe,
					"stderr":err||outpipe])+
				      ((in && (["stdin":in])) || ([])));
  if(out)
    out->close();
  if(callback)
    while(!p->status())
      callback();
  return p->wait();
}

int run_cdrecord(array(string) args, Stdio.File|void in, Stdio.File|void out,
		 Stdio.File|void err, function(:void)|void callback)
{
  return do_command(({command_path->cdrecord}) + args,
		    in, out, err, callback) == 0;
}

int run_mkisofs(array(string) args,  Stdio.File|void in, Stdio.File|void out,
		Stdio.File|void err, function(:void)|void callback)
{
  return do_command(({command_path->mkisofs}) + args,
		    in, out, err, callback) == 0;
}

string run_to_string(function(array(string),Stdio.File|void,Stdio.File|void,
			      Stdio.File|void,function(:void)|void:int) fun,
		     array(string) args, int|void err)
{
  [Stdio.File wp, Stdio.File p] = make_pipes();
  string res = "";

  if(!fun(args, 0, wp, err&&wp, lambda() {
				  res += p->read(100,1);
				})) {
    if(err<2)
      gui->get_output_pipe()->write(res+p->read());
    else
      p->read();
    return 0;
  } else
    return res+p->read();
}

// NERO

class YellowBook
{
  constant EDC_crctable_hi = ({
    0x000000, 0x909101, 0x912102, 0x01B003,
    0x924104, 0x02D005, 0x036006, 0x93F107,
    0x948108, 0x041009, 0x05A00A, 0x95310B,
    0x06C00C, 0x96510D, 0x97E10E, 0x07700F,
    0x990110, 0x099011, 0x082012, 0x98B113,
    0x0B4014, 0x9BD115, 0x9A6116, 0x0AF017,
    0x0D8018, 0x9D1119, 0x9CA11A, 0x0C301B,
    0x9FC11C, 0x0F501D, 0x0EE01E, 0x9E711F,
    0x820120, 0x129021, 0x132022, 0x83B123,
    0x104024, 0x80D125, 0x816126, 0x11F027,
    0x168028, 0x861129, 0x87A12A, 0x17302B,
    0x84C12C, 0x14502D, 0x15E02E, 0x85712F,
    0x1B0030, 0x8B9131, 0x8A2132, 0x1AB033,
    0x894134, 0x19D035, 0x186036, 0x88F137,
    0x8F8138, 0x1F1039, 0x1EA03A, 0x8E313B,
    0x1DC03C, 0x8D513D, 0x8CE13E, 0x1C703F,
    0xB40140, 0x249041, 0x252042, 0xB5B143,
    0x264044, 0xB6D145, 0xB76146, 0x27F047,
    0x208048, 0xB01149, 0xB1A14A, 0x21304B,
    0xB2C14C, 0x22504D, 0x23E04E, 0xB3714F,
    0x2D0050, 0xBD9151, 0xBC2152, 0x2CB053,
    0xBF4154, 0x2FD055, 0x2E6056, 0xBEF157,
    0xB98158, 0x291059, 0x28A05A, 0xB8315B,
    0x2BC05C, 0xBB515D, 0xBAE15E, 0x2A705F,
    0x360060, 0xA69161, 0xA72162, 0x37B063,
    0xA44164, 0x34D065, 0x356066, 0xA5F167,
    0xA28168, 0x321069, 0x33A06A, 0xA3316B,
    0x30C06C, 0xA0516D, 0xA1E16E, 0x31706F,
    0xAF0170, 0x3F9071, 0x3E2072, 0xAEB173,
    0x3D4074, 0xADD175, 0xAC6176, 0x3CF077,
    0x3B8078, 0xAB1179, 0xAAA17A, 0x3A307B,
    0xA9C17C, 0x39507D, 0x38E07E, 0xA8717F,
    0xD80180, 0x489081, 0x492082, 0xD9B183,
    0x4A4084, 0xDAD185, 0xDB6186, 0x4BF087,
    0x4C8088, 0xDC1189, 0xDDA18A, 0x4D308B,
    0xDEC18C, 0x4E508D, 0x4FE08E, 0xDF718F,
    0x410090, 0xD19191, 0xD02192, 0x40B093,
    0xD34194, 0x43D095, 0x426096, 0xD2F197,
    0xD58198, 0x451099, 0x44A09A, 0xD4319B,
    0x47C09C, 0xD7519D, 0xD6E19E, 0x46709F,
    0x5A00A0, 0xCA91A1, 0xCB21A2, 0x5BB0A3,
    0xC841A4, 0x58D0A5, 0x5960A6, 0xC9F1A7,
    0xCE81A8, 0x5E10A9, 0x5FA0AA, 0xCF31AB,
    0x5CC0AC, 0xCC51AD, 0xCDE1AE, 0x5D70AF,
    0xC301B0, 0x5390B1, 0x5220B2, 0xC2B1B3,
    0x5140B4, 0xC1D1B5, 0xC061B6, 0x50F0B7,
    0x5780B8, 0xC711B9, 0xC6A1BA, 0x5630BB,
    0xC5C1BC, 0x5550BD, 0x54E0BE, 0xC471BF,
    0x6C00C0, 0xFC91C1, 0xFD21C2, 0x6DB0C3,
    0xFE41C4, 0x6ED0C5, 0x6F60C6, 0xFFF1C7,
    0xF881C8, 0x6810C9, 0x69A0CA, 0xF931CB,
    0x6AC0CC, 0xFA51CD, 0xFBE1CE, 0x6B70CF,
    0xF501D0, 0x6590D1, 0x6420D2, 0xF4B1D3,
    0x6740D4, 0xF7D1D5, 0xF661D6, 0x66F0D7,
    0x6180D8, 0xF111D9, 0xF0A1DA, 0x6030DB,
    0xF3C1DC, 0x6350DD, 0x62E0DE, 0xF271DF,
    0xEE01E0, 0x7E90E1, 0x7F20E2, 0xEFB1E3,
    0x7C40E4, 0xECD1E5, 0xED61E6, 0x7DF0E7,
    0x7A80E8, 0xEA11E9, 0xEBA1EA, 0x7B30EB,
    0xE8C1EC, 0x7850ED, 0x79E0EE, 0xE971EF,
    0x7700F0, 0xE791F1, 0xE621F2, 0x76B0F3,
    0xE541F4, 0x75D0F5, 0x7460F6, 0xE4F1F7,
    0xE381F8, 0x7310F9, 0x72A0FA, 0xE231FB,
    0x71C0FC, 0xE151FD, 0xE0E1FE, 0x7070FF
  });

  constant EDC_crctable_lo = ({
    0x00, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x00,
    0x00, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x00,
    0x00, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x00,
    0x00, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x00,
    0x00, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x00,
    0x00, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x00,
    0x00, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x00,
    0x00, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x00,
    0x00, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x00,
    0x00, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x00,
    0x00, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x00
  });

  constant rs_l12_log = "\0\0\1\31\2""2\32Æ\3ß3î\33hÇK\4dà\16""4\215ï"
  "\201\34ÁiøÈ\bLq\5\212e/á$\17!5\223\216Úð\22\202E\35µÂ}j'ù¹É\232\txM"
  "är¦\6¿\213bfÝ0ýâ\230%³\20\221\"\210""6Ð\224Î\217\226Û½ñÒ\23\\\203"
  "8F@\36B¶£ÃH~nk:(Tú\205º=Ê^\233\237\n\25y+NÔå¬só§W\7pÀ÷\214\200c\rgJ"
  "Þí1Åþ\30ã¥\231w&¸´|\21D\222Ù# \211.7?Ñ[\225¼ÏÍ\220\207\227²Üü¾aòVÓ«"
  "\24*]\236\204<9SGmA¢\37-CØ·{¤vÄ\27Iì\177\14oöl¡;R)\235Uªû`\206±»Ì>Z"
  "ËY_°\234© Q\13õ\26ëzu,×O®Õéæç­ètÖôê¨PX¯";

  constant rs_l12_alog = "\1\2\4\b\20 @\200\35:tèÍ\207\23&L\230-Z´uêÉ"
  "\217\3\6\14\30""0`À\235'N\234%J\224""5jÔµwîÁ\237#F\214\5\n\24(P ]ºi"
  "Ò¹oÞ¡_¾aÂ\231/^¼eÊ\211\17\36<xðýçÓ»kÖ±\177þáß£[¶qâÙ¯C\206\21\"D\210"
  "\r\32""4hÐ½gÎ\201\37>|øíÇ\223;vìÅ\227""3fÌ\205\27.\\¸mÚ©O\236!B\204"
  "\25*T¨M\232)R¤UªI\222""9räÕ·sæÑ¿cÆ\221?~üå×³{öñÿãÛ«K\226""1bÄ\225"
  "7nÜ¥W®A\202\31""2dÈ\215\7\16\34""8pàÝ§S¦Q¢Y²yòùïÃ\233+V¬E\212\t\22$"
  "H\220=zôõ÷óûëË\213\13\26,X°}úéÏ\203\33""6lØ­G\216"*2;

  constant DP = Array.transpose(({
    ({231,229,171,210,240,17,67,215,43,120,8,199,74,102,220,251,95,175,
      87,166,113,75,198,25,0}),
    ({230,172,211,241,18,68,216,44,121,9,200,75,103,221,252,96,176,88,
      167,114,76,199,26,1,0}),
  }));

  constant DQ = Array.transpose(({
    ({190,96,250,132,59,81,159,154,200,7,111,245,10,20,41,156,168,79,173,
      231,229,171,210,240,17,67,215,43,120,8,199,74,102,220,251,95,175,
      87,166,113,75,198,25,0}),
    ({97,251,133,60,82,160,155,201,8,112,246,11,21,42,157,169,80,174,232,
      230,172,211,241,18,68,216,44,121,9,200,75,103,221,252,96,176,88,
      167,114,76,199,26,1,0}),
  }));

  int build_edc(string s)
  {
    int rlo = 0, rhi = 0;
    foreach(values(s), int n) {
      n ^= rlo;
      rlo = EDC_crctable_lo[n] ^ (rhi & 0xff);
      rhi = EDC_crctable_hi[n] ^ (rhi>>8);
    }
    return (rhi<<8)|rlo;
  }

  string encode_P(string buf)
  {
    int i=0, j=0;
    array(int) P = allocate(43*2*2);
    [int DP0, int DP1] = DP[0];
    foreach(values(buf), int data) {
      if(data) {
	int base = rs_l12_log[data];
	P[j] ^= rs_l12_alog[base + DP0];
	P[j+43*2] ^= rs_l12_alog[base + DP1];
      }
      if(++j == 2*43) { j=0; [DP0,DP1] = DP[++i]; }
    }
    return (string)P;
  }

  string encode_Q(string buf)
  {
    int i=0, j=0;
    array(int) Q = allocate(26*2*2);
    [int DQ0, int DQ1] = DQ[0];
    foreach(values(buf), int data) {
      if(data) {
	int base = rs_l12_log[data];
	Q[j] ^= rs_l12_alog[base + DQ0];
	Q[j+26*2] ^= rs_l12_alog[base + DQ1];
      }
      if(j&1) {
	if(++i == 43)
	  { i = 0; j -= 16; }
	if((j-=3)<0)
	  j += 52;
	[DQ0,DQ1] = DQ[i];
      } else j++;
    }
    return (string)Q;
  }
}

class NeroImage
{
  static private inherit YellowBook;

  static Stdio.File f = Stdio.File();
  static string cues = "", etnf = "";
  static int start_byte;
  static int sector_addr_m, sector_addr_s, sector_addr_f;

#define BCD(n) ((n)+((n)/10)*6)

  void write_mode2(Stdio.File f, string data)
  {
    data = "\0\0\10\0\0\0\10\0"+data;
    data += sprintf("%-4c", build_edc(data));
    data += encode_P("\0\0\0\0"+data);
    data += encode_Q("\0\0\0\0"+data);
    data = sprintf("%1c%1c%1c\2%s",
		   BCD(sector_addr_m),
		   BCD(sector_addr_s),
		   BCD(sector_addr_f),
		   data);
    //  data ^= scramble_string;
    f->write("\0\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0"+data);
    if(++sector_addr_f >= 75) {
      sector_addr_f = 0;
      if(++sector_addr_s >= 60) {
	sector_addr_s = 0;
	sector_addr_m++;
      }
    }
  }

  void add_cue(Stdio.File f, int a, int b)
  {
    int p = f->tell()/2352;
    cues += sprintf("\1%1c%1c\0\0%1c%1c%1c", a, b, p/4500, (p/75)%60, p%75);
  }
  
  void add_etnf(Stdio.File f)
  {
    etnf += sprintf("%4c", f->tell() - start_byte);
  }
  
  void write_epilog()
  {
    int l = f->tell();
    
    f->write(sprintf("CUES%4c%s", sizeof(cues), cues));
    
    string s;
    s = "\x00\x00\x00\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    s += "\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    s += "\x00\x00\x09\x30\x07\x00\x00\x01\x00\x00\x00\x00\x00\x05\x62\x20";
    s += "\x00\x10\x38\xc0";
    f->write(sprintf("DAOI%4c%s", sizeof(s), s));
    
    etnf += "\x00\x00\x00\x06\x00\x00\x2d\xb6\x00\x00\x00\x00";
    f->write(sprintf("ETNF%4c%s", sizeof(etnf), etnf));
    
    s = "\0\0\0\1";
    f->write(sprintf("SINF%4c%s", sizeof(s), s));
    
    s = "\0\0\0\1";
    f->write(sprintf("SINF%4c%s", sizeof(s), s));
    
    s = "";
    f->write(sprintf("END!%4c%s", sizeof(s), s));
    
    f->write(sprintf("NERO%4c", l));
  }

}


// Disk creation interface

class Burner
{
  int burn_audio(function(int,int:void)|void progress);
  int burn_data(array(string) mkisofsargs, int data_size, string|void ip_bin,
		function(int,int:void)|void progress);
}

class NeroBurner
{
  static inherit NeroImage;

  int burn_audio(function(int,int:void)|void progress)
  {
    int i;

    string fn = gui->query_filename("Select filename for NERO image");

    if(!fn)
      return 0;

    f->open(fn, "wct");

    /* lead-in */
    start_byte = f->tell();
    add_cue(f, 0, 0);
    add_cue(f, 1, 0);
    for(i=0; i<150; i++) {
      if(progress)
	progress(i, 150+302);
      f->write("\0"*2352);
    }
    
    /* track 1 */
    add_cue(f, 1, 1);
    for(i=0; i<302; i++) {
      if(progress)
	progress(150+i, 150+302);
      f->write("\0"*2352);
    }
    add_etnf(f);

    return 1;
  }

  int burn_data(array(string) mkisofsargs, int data_size, string|void ip_bin,
		function(int,int:void)|void progress)
  {
    [Stdio.File wpipe, Stdio.File rpipe] = make_pipes();

    /* track 2 */
    start_byte = f->tell();
    sector_addr_m = 2;
    sector_addr_s = 38;
    sector_addr_f = 2;
    add_cue(f, 0xaa, 1);

    int i=0;
    int stream_data()
    {
      string z;
      if((z = rpipe->read(2048)) && sizeof(z)==2048) {
	if(ip_bin && i<16)
	  z = ip_bin[i*2048..i*2048+2047];
	if(progress)
	  progress(i++, data_size);
	write_mode2(f, z);
	return 1;
      } else
	return 0;
    };

    int rc =
      run_mkisofs(({"-C", "0,11702"})+mkisofsargs, 0, wpipe, 0, stream_data);
    while(stream_data());
    rpipe->close();
    
    add_etnf(f);

    write_epilog();

    f->close();

    return rc;
  }

  static void create(string id, int direct_burn)
  {
    if(id != "-nrg") {
      gui->display_message(GUI.FATAL,
			   sprintf("Internal error %O != %O", id, "-nrg"));
      destruct(this_object());
      return;
    }
  }
}

class CdRecordBurner(string dev, int direct_burn)
{
  int burn_audio(function(int,int:void)|void progress)
  {
    [Stdio.File wpipe, Stdio.File rpipe] = make_pipes();
    int i=0;
    int stream_data()
    {
      if(i==302) {
	wpipe->close();
	i++;
	return 1;
      } else if(i<302) {
	wpipe->write("\0"*2352);
	if(progress)
	  progress(i++, 302);
	return 1;
      } else
	return 0;
    };    
    return run_cdrecord(({"dev="+dev, "-multi", "-audio", "-"}),
			rpipe, 0, 0, stream_data);
  }

  int burn_data(array(string) mkisofsargs, int data_size, string|void ip_bin,
		function(int,int:void)|void progress)
  {
    string s = run_to_string(run_cdrecord, ({"dev="+dev, "-msinfo"}), 1);
    string msinfo=0;
    if(!s || !sizeof(s))
      return 0;
    foreach(s/"\n"-({""}), string l)
      if(2==sscanf(l, "%*d,%*d"))
	msinfo = l;
    if(!msinfo) {
      gui->get_output_pipe()->write(s);
      return 0;
    }

    string isofn = 0;
    int ok=1, seq=0;
    Stdio.File spipea, spipeb;
    int i=0;
    int stream_data()
    {
      string z;
      if(spipeb && (z = spipea->read(2048*16)) && sizeof(z)) {
	if(!i && ip_bin)
	  z = ip_bin;
	if(progress)
	  progress(i++, data_size/16);
	if(spipeb->write(z) != sizeof(z))
	  ok = 0;
	return 1;
      } else {
	if(spipeb) {
	  spipeb->close();
	  spipeb = 0;
	}
	return 0;
      }
    };

    if(direct_burn) {
      [Stdio.File wpipe, Stdio.File rpipe] = make_pipes();
      [Stdio.File wpipe2, Stdio.File rpipe2] = make_pipes();
      spipea = rpipe;
      spipeb = wpipe2;
      if(!run_mkisofs(({"-C", msinfo})+mkisofsargs, 0, wpipe, 0,
		      lambda() {
			if(!seq) {
			  seq++;
			  if(!run_cdrecord(({"dev="+dev, "-eject", "-multi",
					     "-xa1", "-"}),
					   rpipe2, 0, 0, stream_data))
			    ok = 0;
			} else
			  stream_data();
		      }))
	ok = 0;
      rpipe2->close();
    } else {
      isofn = tmp_dir+"data.trk";
      Stdio.File iso = Stdio.File();
      if(!iso->open(isofn, "cwt"))
	return 0;
      [Stdio.File wpipe, Stdio.File rpipe] = make_pipes();
      spipea = rpipe;
      spipeb = iso;
      if(!run_mkisofs(({"-C", msinfo})+mkisofsargs, 0, wpipe, 0, stream_data))
	ok = 0;
      while(stream_data());
      spipea->close();
      if(!ok || !iso->open(isofn, "r")) {
	rm(isofn);
	return 0;
      }
      [wpipe, rpipe] = make_pipes();
      spipea = iso;
      spipeb = wpipe;
      i = 0;
      if(!run_cdrecord(({"dev="+dev, "-eject", "-multi",
			 "-xa1", "-"}),
		       rpipe, 0, 0, stream_data))
	ok = 0;
      rpipe->close();
    }
    while(stream_data());
    spipea->close();
    if(isofn) rm(isofn);
    return ok;
  }
}

static mapping(string:program) special_burner = ([
  "-nrg" : NeroBurner,
]);


// ROM files

class ROMFile
{
  static string filename, name;

#ifdef GTK2
  string get_name()
  {
    return (string)map(values(name), lambda(int n) {
				       if(n<32) return n+0xc0;
				       else if(n=='\\') return 0xa5;
				       else if(n=='~') return 0x203e;
				       else if(n<128) return n;
				       else if(n<160) return n+0x60;
				       else return n+0xfec0;
				     });
  }
  void set_name(string n)
  {
    name = (string)map(values(n), lambda(int n) {
				    if(n<128) return n;
				    else if(n>=0xc0 && n<=0xdf) return n-0xc0;
				    else if(n>=0xe0 && n<=0xff) return n-0x60;
				    else if(n==0xa5) return '\\';
				    else if(n==0x203e) return '~';
				    else if(n>=0xff60 && n<0xffc0)
				      return n-0xfec0;
				    else return '?';
				  });
  }
#else
  string get_name() { return name; }
  void set_name(string n) { name = n; }
#endif
  string get_path() { return filename; }

  static local int all_ascii(string s)
  {
    return !sizeof(filter(values(s), lambda(int n) { return n<32 || n>126; }));
  }

  int score_hirom(string data, int size)
  { 
    int score = 0; 
    
    if ((data[0xffdc] + (data[0xffdd] << 8) + 
         data[0xffde] + (data[0xffdf] << 8)) == 0xffff) 
      score += 2; 
    
    if (data[0xffda] == 0x33) 
      score += 2; 
    if ((data[0xffd5] & 0xf) < 4) 
      score += 2; 
    if (!(data[0xfffd] & 0x80)) 
      score -= 4; 
    if (size > 1024 * 1024 * 3) 
      score += 4; 
    if (data[0xffd7]<7 || (1 << (data[0xffd7] - 7)) > 48) 
      score -= 1; 
    if (!all_ascii(data[0xffb0..0xffb0+5])) 
      score -= 1; 
    if (!all_ascii(data[0xffc0..0xffc0+21])) 
      score -= 1; 

    return score; 
  }
  
  int score_lorom(string data, int size)
  { 
    int score = 0; 
    
    if ((data[0x7fdc] + (data[0x7fdd] << 8) + 
         data[0x7fde] + (data[0x7fdf] << 8)) == 0xffff) 
      score += 2; 
    
    if (data[0x7fda] == 0x33) 
      score += 2; 
    if ((data[0x7fd5] & 0xf) < 4) 
      score += 2; 
    if (size <= 1024 * 1024 * 16) 
      score += 2; 
    if (!(data[0x7ffd] & 0x80)) 
      score -= 4; 
    if (data[0x7fd7]<7 || (1 << (data[0x7fd7] - 7)) > 48) 
      score -= 1; 
    if (!all_ascii(data[0x7fb0..0x7fb0+5])) 
      score -= 1; 
    if (!all_ascii(data[0x7fc0..0x7fc0+21])) 
      score -= 1; 

    return score; 
  }
     
  static void analyze_rom(string data, int size)
  {
    string tmpname;

    if(!data || sizeof(data)<0x10000)
      return;

    int losc = score_lorom(data, size);
    int hisc = score_hirom(data, size);
    int o;

    if(losc > hisc)
      o = 0x7fc0; 
    else 
      o = 0xffc0; 

    tmpname = data[o..o+20];

    if(tmpname-"\xff"-"\0" != "")
      name = tmpname;
  }

  static void create(string _filename)
  {
    filename = _filename;
    name = "UNKNOWN";
    Stdio.Stat st = file_stat(filename);
    if(st && st[1]>0 && (!(st[1]&0x7fff) || !((st[1]+0x7e00)&0x7fff)))
      analyze_rom(Stdio.read_bytes(filename, st[1]&0x200, 0x10000), st[1]);
    else
      name = "INVALID";
  }
}

// HTTP download

#define CHUNK_SIZE 8192

class Downloader(static string url, static int|void size)
{

  static int accept_data(string d);
  static mapping(string:string) headers;

  int run(function(int,int:void)|void progress)
  {
    mapping(string:string) r_hdrs = ([]);
    r_hdrs["user-agent"] = sprintf("dreamsnesinstall/%.2f", installer_version);
    Protocols.HTTP.Query q;
    int nredir = 5;
    while(--nredir) {
      q = Protocols.HTTP.get_url(url, 0, r_hdrs);
      if(!q)
	return 0;
      if(q->status != 302 || !q->headers->location)
	break;
      url = q->headers->location;
    }
    if(!nredir)
      // max no of redirects exceeded
      return 0;
    if(q->status != 200)
      return 0;
    headers = copy_value(q->headers);
    string chunk;
    int max_bytes = size || q->total_bytes();
    do {
      chunk = q->incr_data(CHUNK_SIZE);
      if(progress)
	progress(q->downloaded_bytes(), max_bytes);
      accept_data(chunk);
    } while(sizeof(chunk));
    return 1;
  }

  mapping(string:string) get_headers()
  {
    return headers;
  }
}

class StringDownloader
{
  inherit Downloader;

  static string data = "";

  static int accept_data(string d)
  {
    data += d;
    return 1;
  }

  string get_data()
  {
    return data;
  }
}

class FileDownloader
{
  inherit Downloader;

  static Stdio.File file = Stdio.File();

  static int accept_data(string d)
  {
    return file->write(d) == sizeof(d);
  }

  static void create(string url, string fn, int|void size)
  {
    ::create(url, size);
    file->open(fn, "cwt");
  }
}

// Network resource management

class Resource
{
  static string url, md5_digest, filename;
  static int size;

  //! How many bytes of this resource are currently downloaded (0 if none)?
  int currently_downloaded()
  {
    return max(0, Stdio.file_size(filename));
  }

  //! Does this resource exist locally (but not necessarily complete)?
  int exists()
  {
    return currently_downloaded()>0;
  }

  //! Is there an incomplete local copy of this resource?
  int is_partial()
  {
    int n = currently_downloaded();
    return n>0 && n<size;
  }

  //! Does the local resource have the correct checksum?
  static int checksum_ok()
  {
    object md5 = Crypto.md5();
    Stdio.File f = Stdio.File();
    string s;

    if(!f->open(filename, "r"))
      return 0;

    while((s = f->read(65536)) && sizeof(s))
      md5->update(s);

    f->close();

    return sprintf("%@02x", (array(int))md5->digest()) == md5_digest;
  }

  //! Is the local resource valid (exists with right size and checksum)?
  int is_valid()
  {
    return currently_downloaded() == size && checksum_ok();
  }

  //! Try to force the resource to become valid
  int aquire(function(int,int:void)|void progress)
  {
    if(is_valid())
      return 1;

    FileDownloader(url, filename, size)->run(progress);

    return is_valid();
  }

  //! Get the path to the local resource
  string get_path()
  {
    return filename;
  }

  //! Remove the local resource
  void invalidate()
  {
    rm(filename);
  }

  static void create(string _url, int _size, string _digest)
  {
    url = _url;
    size = _size;
    md5_digest = _digest;
    filename = tmp_dir+(url/"/")[-1];
  }
}

// Tar files

class Reader(static Stdio.File f)
{
  int get_size()
  {
    int r, p = f->tell();
    f->seek(-1);
    r = f->tell()+1;
    f->seek(p);
    return r;
  }

  int tell() { return f->tell(); }
  string read(int n) { return f->read(); }
  int close() { return f->close(); }
}

class GZReader
{
  static Stdio.File f;
  static int csize, isize, pos = 0;
  static Gz.inflate inflate = Gz.inflate();
  static string buffer = "";

  int get_size()
  {
    return isize;
  }

  int tell()
  {
    return pos;
  }

  string read(int n)
  {
    int ch;
    while(n > sizeof(buffer) && (ch = csize - f->tell())>0) {
      string d = f->read(ch>32768? 32768 : ch);
      if(!sizeof(d))
	break;
      buffer += inflate->inflate(d);
    }
    string r = buffer[..n-1];
    buffer = buffer[n..];
    pos += sizeof(r);
    return r;
  }

  int close()
  {
    buffer = "";
    csize = pos = 0;
    return f->close();
  }

  static int skip_fextra()
  {
    int xlen;
    return sscanf(f->read(2), "%-2c") && sizeof(f->read(xlen)) == xlen;
  }

  static int skip_zdata()
  {
    string s;
    do {
      s = f->read(1);
      if(s == "") return 0;
    } while(s!="\0");
    return 1;
  }

  void create(Stdio.File _f)
  {
    f = _f;
    f->seek(-8);
    csize = f->tell();
    sscanf(f->read(8), "%*-4c%-4c", isize);
    f->seek(0);
    string hdr;
    if(sizeof(hdr = f->read(10)) != 10 ||
       hdr[..1] != "\x1f\x8b" ||
       ((hdr[3] & 4) && !skip_fextra()) ||
       ((hdr[3] & 8) && !skip_zdata()) ||
       ((hdr[3] & 16) && !skip_zdata()) ||
       ((hdr[3] & 2) && sizeof(f->read(2)) != 2))
      csize = isize = 0;
    else
      inflate->inflate(sprintf("%1c%1c", hdr[2], ((310-hdr[2])<<8)%31));
  }
}

class TarManager
{
  static string my_dir;
  static mapping(string:string) contents = ([]);

  static void recursive_delete(string fn)
  {
    Stdio.Stat st = file_stat(fn);
    if(st && st->isdir)
      foreach(get_dir(fn)||({}), string sub)
	recursive_delete(combine_path(fn, sub));
    rm(fn);
  }

  void cleanup()
  {
    if(!my_dir)
      return;
    recursive_delete(my_dir);
    my_dir = 0;
  }

  int extract(string fn)
  {
    int ok = 0;
    Stdio.File f = Stdio.File();
    if(!f->open(fn, "r"))
      return 0;
    Reader r = (fn[sizeof(fn)-3..]==".gz"? GZReader : Reader)(f);
    int sz = r->get_size();
    gui->progress_popup("Extracting files from "+(fn/"/")[-1]);
    while(r->tell() <= sz) {
      gui->progress_update(r->tell(), sz);
      string hdr = r->read(512);
      if(hdr == "" && r->tell() == sz) {
	ok = 1;
	break;
      }
      if(sizeof(hdr) != 512)
	break;
      array a = array_sscanf(hdr,
			     "%100s%8s%8s%8s%12s%12s%8s"
			     "%c%100s%8s%32s%32s%8s%8s");
      string name;
      sscanf(a[0], "%s%*[\0]", name);
      if(!sizeof(name))
	continue;
      int mode;
      sscanf(a[1], "%o", mode);

      switch(a[7]) {
      case '0':
	int size;
	sscanf(a[4], "%o", size);
	if(Stdio.write_file(my_dir+"/"+name, r->read(size), mode) != size)
	  ok = -1;
	break;
      case '5':
	mkdir(my_dir+"/"+name, mode);
	break;
      }

      if(ok<0)
	break;

      if(name[-1] == '/')
	name = name[..sizeof(name)-2];
      string idx = lower_case((name/"/")[-1]);
      if(!contents[idx])
	contents[idx] = name;

      if(r->tell()&511)
	r->read(512 - (r->tell()&511));
    }
    gui->progress_popdown();
    r->close();
    return ok>0;
  }

  string get_path(string|void sub)
  {
    if(!sub) return my_dir;
    sub = lower_case(sub);
    return contents[sub] && (my_dir+"/"+contents[sub]);
  }

  static void create()
  {
    do my_dir = tmp_dir+"temp"+random(10000); while(file_stat(my_dir));
    atexit(cleanup);
    mkdir(my_dir);
  }
}

// Packages and manifest

class Package
{
  static string name;
  static mapping(string:Package) subpackages;
  static Resource resource;

  string get_name() { return name; }

  Resource get_resource() { return resource; }

  void add_subpackage(string name, Package sub)
  {
    subpackages[name] = sub;
  }

  static void create(mapping(string:string) vars)
  {
    name = vars->name;
    subpackages = ([]);
    resource = Resource(vars->url, (int)vars->size,
			lower_case(vars["md5-digest"]));
  }

}

class Manifest
{
  static mapping(string:Package) applications = ([]);
  static mapping(string:string) attributes = ([]);

  array(string) list_applications()
  {
    return indices(applications);
  }

  Package get_application(string name)
  {
    return applications[name];
  }

  static int parse(string m)
  {
    applications = ([]);
    attributes = ([]);
    foreach((m-"\r")/"\n\n", string section) {
      array(array(string)) tmp =
	map(map(section/"\n", String.trim_whites)-({""}),
	    array_sscanf, "%[^:]: %s");
      mapping(string:string) vars =
     	mkmapping(map(column(tmp, 0), lower_case), column(tmp, 1));
      if(vars->name) {
	Package p = Package(vars);
	if(vars->requires)
	  applications[vars->requires]->add_subpackage(vars->name, p);
	else
	  applications[vars->name] = p;
      } else
	attributes |= vars;
    }
    if(attributes["manifest-version"])
      return 1;
    else
      return 0;
  }

  int input(string m)
  {
    return parse(m);
  }

  int outdated_client()
  {
    return ((float)attributes["required-installer-version"])>installer_version;
  }

  int download_new_client(string fn)
  {
    int rc = 0;

    Resource r = Resource(attributes["installer-update-url"],
			  (int)attributes["installer-update-size"],
			  attributes["installer-update-md5"]);

    if(r->aquire())
    {
      rm(fn);
      rc = mv(r->get_path(), fn);
    }

    r->invalidate();

    return rc;
  }

  static int verify_signature(string manifest, string sig)
  {
    catch {
      mapping signt = decode_PGP(sig)->signature;
      object hash;
      if(signt->digest_algorithm == 2)
	hash = Crypto.sha();
      else
	hash = Crypto.md5();
      hash->update(manifest);
      return PGP_verify(hash, signt,
			decode_PGP(pubkey_data)->public_key);
    };
    return 0;
  }

  int load_from(string url)
  {
    string manifest, sig;
    StringDownloader dl = StringDownloader(url);
    if(!dl->run())
      return 0;
    manifest = dl->get_data();
    dl = StringDownloader(url+".sig");
    if(!dl->run())
      return 0;
    sig = dl->get_data();
    if(!verify_signature(manifest, sig)) {
      gui->display_message(GUI.FATAL, "Manifest did not have a "
			   "correct signature!");
      return 0;
    }
    return input(manifest);
  }
}

// Tasks

class Task
{
  string get_name();

  int|string perform();
}

class FindBinary(string name)
{
  string get_name() { return "Locate "+name+" binary"; }

  string perform()
  {
    array(string) PATH=(getenv("PATH")||"")/":"-({""});
    foreach(({"", ".exe"}), string ext)
      foreach(({combine_path(__FILE__,".."), "."})+PATH, string elt) {
	string fn = combine_path(elt, name+ext);
	if(search(fn, "/")<0) fn="./"+fn;
	Stdio.Stat st = file_stat(fn);
	if(st && (st->mode & 0111))
	  return command_path[name] = fn;
      }
    return 0;
  }
}

class CheckCdRecord
{
  string get_name() { return "Check that cdrecord/mkisofs works"; }

  int perform()
  {
    return run_cdrecord(({"-version"})) && run_mkisofs(({"-version"}));
  }

}

class CheckGraftPoints
{
  string get_name() { return "Check if mkisofs needs -graft-points"; }

  int|string perform()
  {
    if(run_to_string(run_mkisofs, ({"-graft-points", "-version"}), 2)) {
      g_mkisofs_needs_graft_points = 1;
      return "Yes";
    } else
      return "No";
  }
}

class ScanBus
{
  string get_name() { return "Scan for drives"; }

  constant recoverable = "Probe for CD-ROM units failed.  "
  "Only image file creation will be available";

  int perform()
  {
    string scan;
    array(array(string)) drives = ({});

    if(!(scan = run_to_string(run_cdrecord,({"-scanbus"})))) {
      g_destination_locations = ({ });
      return 0;
    }

    foreach(scan/"\n", string line) {
      int dev1, dev2, dev3;
      string vendor, name;
      if(7==sscanf(String.trim_all_whites(line),
		   "%d,%d,%d%*s'%s' '%s'%*sCD-ROM",
		   dev1,dev2,dev3,vendor,name))
	drives += ({ ({ sprintf("%d,%d,%d %s %s",
				dev1, dev2, dev3, vendor, name),
			sprintf("%d,%d,%d", dev1, dev2, dev3) }) });
    }

    g_destination_locations = drives;

    return sizeof(drives)>0;
  }
}

class Burn(Burner burner)
{
  int data_size;

  array(Task) tasks()
  {
    return ({
      class {
	string get_name() { return "Calculate data track size"; }
	
	int perform()
	{
	  string s = run_to_string(run_mkisofs, ({"-print-size"})+
				   g_mkisofsargs, 1);
	  if(!s || !sizeof(s))
	    return 0;
	  foreach(reverse(s/"\n"-({""})), string l)
	    if(2==sscanf(l, "%*s = %d", data_size))
	      return 1;
	  gui->get_output_pipe()->write(s);
	  return 0;
	} 
      }(),
      class {
	string get_name() { return "Create audio track"; }

	int perform()
	{
	  gui->progress_popup("Writing session 1 (audio)");
	  int rc = burner->burn_audio(gui->progress_update);
	  gui->progress_popdown();
	  return rc;
	} 
      }(),
      class {
	string get_name() { return "Create data track"; }

	int perform()
	{
	  string ip_bin=0;
	  if(g_ipbin_path)
	    if(!(ip_bin = Stdio.read_file(g_ipbin_path)))
	      return 0;

	  gui->progress_popup("Writing session 2 (data)");
	  int rc = 
	    burner->burn_data(g_mkisofsargs, data_size, ip_bin,
			      gui->progress_update);
	  gui->progress_popdown();
	  return rc;
	} 
      }(),
    });
  }
}

class CollectRoms(array(ROMFile) roms)
{
  string get_name() { return "Collect ROM files"; }

  static multiset(string) used = (<>);
  static int seq=0;

  static string cleanup_filename(string fn)
  {
    fn = filter((replace(upper_case(fn), ({"\\", " "}), ({"/", "_"}))/"/")[-1],
		lambda(int n) {
		  return (n>='A' && n<='Z') ||
		    (n>='0' && n<='9') ||
		    n == '.' || n == '_';
		})[..30];
    array(string) parts = fn/".";
    if(sizeof(parts)>2)
      fn = parts[..sizeof(parts)-2]*"_"+"."+parts[-1];
    while(!sizeof(fn) || used[fn])
      fn = sprintf("%'_'-25.25s_%d", fn, (seq++));
    used[fn] = 1;
    return fn;
  }

  int perform()
  {
    string lst1fn = tmp_dir+"ROMS.LST";
    string lst2fn = tmp_dir+"path.lst";
    string markerfn = tmp_dir+"NO_ROMS.HERE";
    Stdio.File lst1 = Stdio.File(), lst2 = Stdio.File(), marker = Stdio.File();
    if(!lst1->open(lst1fn, "cwt") || !lst2->open(lst2fn, "cwt") ||
       !marker->open(markerfn, "cwt"))
      return 0;
    foreach(roms, ROMFile rom) {
      string nice = cleanup_filename(rom->get_path());
      lst1->write("%s:%s\n", nice, rom->get_name());
      lst2->write("roms/"+nice+"="+rom->get_path()+"\n");
    }
    lst1->close();
    lst2->close();
    marker->close();
    g_mkisofsargs += ({ "-path-list", lst2fn, "ROMS.LST="+lst1fn,
			"NO_ROMS.HERE="+markerfn });
    return 1;
  }
}

class DownloadPackage(Package p)
{
  string get_name() { return "Download "+p->get_name(); }

  string|int perform()
  {
    Resource r = p->get_resource();
    if(r->is_valid())
      return "Cached";
    gui->progress_popup("Downloading "+p->get_name());
    int res = r->aquire(gui->progress_update);
    gui->progress_popdown();
    return res;
  }
}

class ExtractPackage(Package p, TarManager t)
{
  string get_name() { return "Extract "+p->get_name(); }

  static string wash_volid(string n)
  {
    return filter(replace(upper_case(n), " ", "_"),
		  lambda(int n) {
		    return n=='_' ||
		      (n>='0' && n<='9') ||
		      (n>='A' && n<='Z');
		  })[..31];
  }

  string|int perform()
  {
    Resource r = p->get_resource();
    if(!r->is_valid())
      return 0;
    if(!t->extract(r->get_path()))
      return 0;

    if(search(g_mkisofsargs, "-V")<0)
      g_mkisofsargs = ({ "-V", wash_volid(p->get_name()) })+g_mkisofsargs;

    string cdpath = t->get_path("cd");
    if(!cdpath)
      return 0;
    g_mkisofsargs += ({ cdpath });
    if(!g_ipbin_path)
      g_ipbin_path = t->get_path("ip.bin");
    return 1;
  }
}

int perform_tasks(array(Task) tasks)
{
  gui->display_checklist(tasks->get_name());
  string|int res;
  for(int i=0; i<sizeof(tasks); i++)
    if(res = tasks[i]->perform())
      gui->checklist_result(i, res);
    else {
      gui->checklist_result(i, 0);
      if(tasks[i]->recoverable) {
	if(stringp(tasks[i]->recoverable))
	  gui->display_message(GUI.WARNING, tasks[i]->recoverable);
      } else
	return 0;
    }
  gui->remove_checklist();
  return 1;
}


// Main

static int main2(int argc, array(string) argv)
{
  gui = GUIProxy(GtkGUI, argv);
  gui->status_popup("Requesting manifest...");
  sleep(2);
    
  Manifest m = Manifest();
  
  if(!m->load_from(root_resource)) {
    gui->display_message(GUI.FATAL, "Failed to retrieve manifest!");
    return 1;
  }
  
  if(m->outdated_client()) {
    
    gui->status_popup("Downloading new client version...");
    sleep(2);
    
    if(!m->download_new_client(__FILE__)) {
      gui->display_message(GUI.FATAL, "Failed to get new client script!");
      return 1;
    } else {
      gui->cleanup();
      return ([function(int,array(string):int)]compile_file(__FILE__)()->main)
	(argc, argv);
    }
  }
  
  gui->status_popdown();

  if(!perform_tasks(({FindBinary("cdrecord"), FindBinary("mkisofs"),
		      CheckCdRecord(), CheckGraftPoints(), ScanBus()}))) {
    string message = "System setup checks failed.";
    if(!command_path->cdrecord)
      message += "\n\nYou don't seem to have cdrecord installed.\n"
	"Please download it from "+cdrecord_homepage;
    else if(!command_path->mkisofs)
      message += "\n\nYou don't seem to have mkisofs installed.\n"
	"Please download it from "+cdrecord_homepage;
    else
      message += "\n\nMaybe you need a newer cdrecord or mkisofs?\n"
	"Please check "+cdrecord_homepage+" for updates.\n"
	"Recommended version is cdrtools-1.10.";
    gui->display_message(GUI.FATAL, message);
    return 1;
  }

  g_destination_locations += ({({"NERO image file", "-nrg"})});

  gui->display_applications(m->list_applications());

  gui->display_destinations(column(g_destination_locations, 0));

  [string dest_burner, int dburn, string selected_app, array(ROMFile) roms] =
    gui->finalize_selections();
  dest_burner = (({0})+column(g_destination_locations, 1))
    [search(column(g_destination_locations, 0), dest_burner)+1];

  Package p = m->get_application(selected_app);
  TarManager t = TarManager();

  g_mkisofsargs = ({ "-f", "-l", "-L", "-d" });
  if(g_mkisofs_needs_graft_points)
    g_mkisofsargs += ({ "-graft-points" });

  if(!perform_tasks(({CollectRoms(roms),
		      DownloadPackage(p),ExtractPackage(p,t)})+
		    Burn((special_burner[dest_burner]||CdRecordBurner)
			 (dest_burner, dburn))->tasks())) {
    gui->display_message(GUI.FATAL, "Disc creation FAILED!");
    t->cleanup();
    return 1;
  } 
  t->cleanup();
  gui->display_message(GUI.INFO, "Disc creation complete.");

  return 0;
}

int main(int argc, array(string) argv)
{
  mixed bt = catch {
    exit(main2(argc, argv));
  };
  
  werror("Fatal execution error:\n"+describe_backtrace(bt));

  exit(1);
}
