#include <ec.h>
#include <ec_plugins.h>
#include <ec_hook.h> 
#include <stdlib.h>
#include <string.h>
#include <time.h>
int plugin_load(void *);

static int dummy_init(void *);
static int dummy_fini(void *);
static void parse_tcp(struct packet_object *);


struct plugin_ops dummy_ops = { 
   .ettercap_version =  EC_VERSION,                        
   .name =              "drop_random_packages",  
   .info =              "Dropea paquetes al azar (TP seg inf)",  
   .version =           "3.0",   
   .init =              &dummy_init,
   .fini =              &dummy_fini,
};

int plugin_load(void *handle) 
{
   DEBUG_MSG("tp seg plugin load function");
   return plugin_register(handle, &dummy_ops);
}

static int dummy_fini(void *dummy) 
{
   (void) dummy;
   hook_del(HOOK_PACKET_TCP, &parse_tcp);
   USER_MSG("tp seg: plugin finalization\n");
   return PLUGIN_FINISHED;
}

static int dummy_init(void *dummy) 
{
   (void) dummy;
   srand(time(NULL));
   USER_MSG("tp seg: plugin running...\n");
   hook_add(HOOK_PACKET_TCP, &parse_tcp);
   return PLUGIN_RUNNING;
}

static void parse_tcp(struct packet_object *po)
{
    bool mustBeDelete = rand() & 1;
   if (mustBeDelete)
   {
      USER_MSG("tp seg:Mark package as dropped..\n");       
      po->flags |= PO_DROPPED;
   }
}