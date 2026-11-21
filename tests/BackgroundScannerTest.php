<?php

/**
 * SPDX-FileCopyrightText: 2018-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2017 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests;

use OC\Files\Storage\Temporary;
use OCA\Files_Antivirus\BackgroundJob\BackgroundScanner;
use OCA\Files_Antivirus\ItemFactory;
use OCA\Files_Antivirus\Scanner\IScanner;
use OCA\Files_Antivirus\Scanner\ScannerFactory;
use OCA\Files_Antivirus\Status;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Files\Config\IUserMountCache;
use OCP\Files\Folder;
use OCP\Files\IMimeTypeLoader;
use OCP\Files\IRootFolder;
use OCP\IConfig;
use OCP\IDBConnection;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;
use Test\Traits\MountProviderTrait;
use Test\Traits\UserTrait;

#[Group('DB')]
class BackgroundScannerTest extends TestBase {
	use UserTrait;
	use MountProviderTrait;

	private Folder $homeDirectory;
	private Folder $externalDirectory;

	protected function setUp(): void {
		parent::setUp();

		$this->createUser('av', 'av');
		$storage = new TemporaryHome();
		$storage->mkdir('files');
		$storage->getScanner()->scan('');

		$external = new Temporary();
		$external->getScanner()->scan('');

		$this->registerMount('av', $storage, 'av');
		$this->registerMount('av', $external, 'av/files/external');

		$this->loginAsUser('av');
		$root = Server::get(IRootFolder::class);
		$this->homeDirectory = $root->getUserFolder('av');
		$this->externalDirectory = $this->homeDirectory->get('external');
	}

	private function markAllScanned() {
		$now = time();
		$db = Server::get(IDBConnection::class);

		$db->getQueryBuilder()->delete('files_antivirus')->executeStatement();

		$query = $db->getQueryBuilder();
		$query->select('fileid')
			->from('filecache');
		$fileIds = $query->executeQuery()->fetchAll(\PDO::FETCH_COLUMN);

		$query = $db->getQueryBuilder();
		$query->insert('files_antivirus')
			->values([
				'fileid' => $query->createParameter('fileid'),
				'check_time' => $now,
			]);
		foreach ($fileIds as $fileId) {
			$query->setParameter('fileid', $fileId);
			$query->executeStatement();
		}
	}

	private function getBackgroundScanner(): BackgroundScanner {
		$scannerFactory = $this->createMock(ScannerFactory::class);
		$status = $this->getMockBuilder(Status::class)
			->disableOriginalConstructor()
			->onlyMethods(['getNumericStatus', 'getDetails'])->getMock();
		$status->method('getNumericStatus')->willReturn(Status::SCANRESULT_CLEAN);
		$status->method('getDetails')->willReturn('');
		$scanner = $this->createMock(IScanner::class);
		$scanner->method('scan')
			->willReturn($status);
		$scannerFactory->method('getScanner')
			->willReturn($scanner);
		return new BackgroundScanner(
			Server::get(ITimeFactory::class),
			$scannerFactory,
			$this->config,
			Server::get(IRootFolder::class),
			Server::get(LoggerInterface::class),
			Server::get(IDBConnection::class),
			Server::get(IMimeTypeLoader::class),
			Server::get(ItemFactory::class),
			Server::get(IUserMountCache::class),
			Server::get(IEventDispatcher::class),
			Server::get(IConfig::class),
			false
		);
	}

	private function updateScannedTime(int $fileId, int $time) {
		$db = Server::get(IDBConnection::class);

		$query = $db->getQueryBuilder();
		$query->update('files_antivirus')
			->set('check_time', $query->createNamedParameter($time))
			->where($query->expr()->eq('fileid', $query->createNamedParameter($fileId)));
		$query->executeStatement();
	}

	public function testGetUnscannedFiles() {
		$this->markAllScanned();

		$scanner = $this->getBackgroundScanner();
		$newFileId = $this->homeDirectory->newFile('foo', 'bar')->getId();
		$this->homeDirectory->getParent()->newFile('outside', 'bar')->getId();

		$outdated = iterator_to_array($scanner->getUnscannedFiles());
		$this->assertEquals([$newFileId], $outdated);
	}

	public function testGetUnscannedFilesExternal() {
		$this->markAllScanned();

		$scanner = $this->getBackgroundScanner();
		$newFileId = $this->homeDirectory->newFile('external/foo2', 'bar2')->getId();

		$outdated = iterator_to_array($scanner->getUnscannedFiles());
		$this->assertEquals([$newFileId], $outdated);
	}

	public function testGetUnscannedFilesIsOrdered() {
		$this->markAllScanned();

		$scanner = $this->getBackgroundScanner();
		$ids = [];
		for ($i = 0; $i < 5; $i++) {
			$ids[] = $this->homeDirectory->newFile("ordered$i", 'bar')->getId();
		}
		sort($ids);

		$this->assertEquals($ids, iterator_to_array($scanner->getUnscannedFiles()));
		$this->assertEquals(array_slice($ids, 0, 2), iterator_to_array($scanner->getUnscannedFiles(2)));
	}

	public function testGetUnscannedFilesObjectStoreHome() {
		$this->markAllScanned();

		$storage = new TemporaryObjectHome();
		$storage->mkdir('files');
		$storage->mkdir('files_versions');
		$storage->mkdir('files_trashbin');
		$storage->file_put_contents('files/foo', 'bar');
		$storage->file_put_contents('files_versions/foo.v1', 'bar');
		$storage->file_put_contents('files_trashbin/foo.d1', 'bar');
		$storage->getScanner()->scan('');

		$scanner = $this->getBackgroundScanner();
		$unscanned = iterator_to_array($scanner->getUnscannedFiles());
		$this->assertEquals([$storage->getCache()->getId('files/foo')], $unscanned);
	}

	public function testUnreachableFilesDoNotBlockTheQueue() {
		$this->markAllScanned();

		// entries no user can reach, older than the user's new file
		$orphan = new \OC\Files\Storage\Temporary();
		for ($i = 0; $i < 3; $i++) {
			$orphan->file_put_contents("orphan$i", 'bar');
		}
		$orphan->getScanner()->scan('');
		$orphanIds = array_map(fn ($i) => $orphan->getCache()->getId("orphan$i"), range(0, 2));
		// the storage scan assigns ids in directory listing order, not by name
		sort($orphanIds);

		$newFileId = $this->homeDirectory->newFile('foo', 'bar')->getId();

		$scanner = $this->getBackgroundScanner();
		$this->assertEquals([...$orphanIds, $newFileId], iterator_to_array($scanner->getUnscannedFiles()));

		// a batch of 3 takes only the unreachable entries: none is scanned, all are recorded
		$this->assertEquals(0, $scanner->scan(3));
		$this->assertEquals([$newFileId], iterator_to_array($scanner->getUnscannedFiles()));

		// so the next batch reaches the user's file
		$this->assertEquals(1, $scanner->scan(3));
		$this->assertEquals([], iterator_to_array($scanner->getUnscannedFiles()));
	}

	public function testGetOutdatedFiles() {
		$newFileId = $this->homeDirectory->newFile('foo', 'bar')->getId();
		$this->markAllScanned();

		$scanner = $this->getBackgroundScanner();

		$outdated = iterator_to_array($scanner->getOutdatedFiles());
		$this->assertEquals([], $outdated);

		$this->updateScannedTime($newFileId, time() - (30 * 24 * 60 * 60));
		$outdated = iterator_to_array($scanner->getOutdatedFiles());
		$this->assertEquals([$newFileId], $outdated);
	}

	public function testTestScanFiles() {
		$this->markAllScanned();

		$scanner = $this->getBackgroundScanner();
		$newFileId = $this->homeDirectory->newFile('foo', 'bar')->getId();

		$outdated = iterator_to_array($scanner->getUnscannedFiles());
		$this->assertEquals([$newFileId], $outdated);

		$scanner->scan(PHP_INT_MAX);

		$outdated = iterator_to_array($scanner->getUnscannedFiles());
		$this->assertEquals([], $outdated);
	}
}
