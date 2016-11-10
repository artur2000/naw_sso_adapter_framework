<?php
/**
 * Created by IntelliJ IDEA.
 * 
 *  (c) Q3i GmbH, Düsseldorf, Germany
 *  http://www.q3i.de
 */

namespace Q3i\NawSso\EventListener;

/**
 * @ignore
 */
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Class UserCreationSubscriber
 * @package Q3i\NawSso\EventListener
 */
class UserCreationSubscriber implements EventSubscriberInterface
{
    /**
     * @return array
     */
    static public function getSubscribedEvents()
    {
        return array(
            'q3i.naw_sso.username_taken'	=> 'onUsernameTaken'
        );
    }
    
    public function onUsernameTaken($event) {
        
    }

}